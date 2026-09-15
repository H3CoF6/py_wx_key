#include "linux_scanner.h"

#include <elf.h>

#include <cstring>
#include <fstream>

LinuxScanner::LinuxScanner() = default;
LinuxScanner::~LinuxScanner() = default;

bool LinuxScanner::LoadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    const auto size = static_cast<size_t>(file.tellg());
    if (size == 0) return false;
    file.seekg(0, std::ios::beg);
    fileBuffer_.resize(size);
    if (!file.read(reinterpret_cast<char*>(fileBuffer_.data()), static_cast<std::streamsize>(size))) {
        return false;
    }
    return true;
}

bool LinuxScanner::GetSectionByName(const char* name, SectionInfo& outSec) {
    if (fileBuffer_.empty()) return false;

    const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(fileBuffer_.data());
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_CLASS] != ELFCLASS64) return false;

    const auto* shdrs = reinterpret_cast<const Elf64_Shdr*>(fileBuffer_.data() + ehdr->e_shoff);
    const auto* shstrtab = &shdrs[ehdr->e_shstrndx];
    const auto* strtab = reinterpret_cast<const char*>(fileBuffer_.data() + shstrtab->sh_offset);

    for (int i = 0; i < ehdr->e_shnum; ++i) {
        const char* secName = strtab + shdrs[i].sh_name;
        if (std::strcmp(secName, name) == 0) {
            outSec.va = shdrs[i].sh_addr;
            outSec.offset = shdrs[i].sh_offset;
            outSec.size = shdrs[i].sh_size;
            outSec.data = fileBuffer_.data() + shdrs[i].sh_offset;
            return true;
        }
    }
    return false;
}

uintptr_t LinuxScanner::FindStringInRodata(const SectionInfo& rodata, const char* str) {
    const size_t len = std::strlen(str);
    if (rodata.size < len) return 0;
    for (size_t i = 0; i <= rodata.size - len; ++i) {
        if (std::memcmp(rodata.data + i, str, len) == 0) {
            return rodata.va + i;
        }
    }
    return 0;
}

// 寻找 lea rsi, [rip+disp]（48 8d 35 xx xx xx xx）且目标地址 == targetVA
std::vector<uintptr_t> LinuxScanner::FindLeaRsiXrefs(const SectionInfo& text, uintptr_t targetVA) {
    std::vector<uintptr_t> refs;
    for (size_t i = 0; i + 7 <= text.size; ++i) {
        if (text.data[i] == 0x48 && text.data[i + 1] == 0x8D && text.data[i + 2] == 0x35) {
            int32_t disp = 0;
            std::memcpy(&disp, text.data + i + 3, sizeof(disp));
            const uintptr_t insnVA = text.va + i;
            const uintptr_t dst = insnVA + 7 + static_cast<intptr_t>(disp);
            if (dst == targetVA) refs.push_back(insnVA);
        }
    }
    return refs;
}

uintptr_t LinuxScanner::ScanBackwardsForPrologue(const SectionInfo& text, uintptr_t startVA) {
    if (startVA < text.va || startVA > text.va + text.size) return 0;

    const size_t startOffset = startVA - text.va;
    for (size_t i = startOffset; i > 0 && (startOffset - i) < 0x500; --i) {
        if (text.data[i] == 0x55 && text.data[i + 1] == 0x41 && text.data[i + 2] == 0x57) {
            return text.va + i;
        }
    }
    return 0;
}

bool LinuxScanner::SearchForHookAddress(const std::string& execPath, ScanResult& result) {
    if (!LoadFile(execPath)) {
        result.msg = "无法打开或读取可执行文件";
        return false;
    }

    SectionInfo rodata, text;
    if (!GetSectionByName(".rodata", rodata) || !GetSectionByName(".text", text)) {
        result.msg = "未找到 .rodata 或 .text 段";
        return false;
    }

    const uintptr_t strVA = FindStringInRodata(rodata, "com.Tencent.WCDB.Config.Cipher");
    if (!strVA) {
        result.msg = "未在 .rodata 找到锚点字符串";
        return false;
    }

    const auto rsiRefs = FindLeaRsiXrefs(text, strVA);
    if (rsiRefs.empty()) {
        result.msg = "未找到锚点字符串的 lea rsi 交叉引用";
        return false;
    }


    // 字符串 xref 前一条指令应为 lea rdi,[rip+disp]（第二个字符串地址）
    uintptr_t unkVA = 0;
    const uintptr_t xref1 = rsiRefs[0];
    const size_t offset = xref1 - text.va;
    if (offset >= 7 && text.data[offset - 7] == 0x48 && text.data[offset - 6] == 0x8D && text.data[offset - 5] == 0x3D) {
        int32_t disp = 0;
        std::memcpy(&disp, text.data + offset - 4, sizeof(disp));
        unkVA = (text.va + offset - 7) + 7 + static_cast<intptr_t>(disp);
    } else {
        result.msg = "字符串 xref 前未找到 lea rdi";
        return false;
    }

    const auto unkRefs = FindLeaRsiXrefs(text, unkVA);
    if (unkRefs.empty()) {
        result.msg = "未找到 lea rsi 指向第二字符串";
        return false;
    }

    const uintptr_t headVA = ScanBackwardsForPrologue(text, unkRefs[0]);
    if (!headVA) {
        result.msg = "未找到函数序言 (55 41 57)";
        return false;
    }

    result.targetVA = headVA;
    result.msg = "Success";
    return true;
}