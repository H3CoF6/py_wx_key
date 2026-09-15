#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ScanResult {
    uintptr_t targetVA = 0;  // ELF 虚拟地址（相对基址）；运行时地址 = 加载基址 + targetVA
    std::string msg;
};

// 零特权锚点推导：读微信可执行文件，定位"登录 PBKDF 配置写入"函数（sink）。
// 推导步骤（Xkey 已验证，微信 4.x 迄今仅两个版本，无需任何下发机制）：
//   .rodata 找 "com.Tencent.WCDB.Config.Cipher"
//   -> .text 找 lea rsi,[rip+disp] 交叉引用
//   -> 回溯 7 字节找 lea rdi,[rip+disp]（第二个字符串）
//   -> 找该字符串的 lea rsi 引用 -> 向前 <=0x500 扫 55 41 57 函数头
class LinuxScanner {
public:
    LinuxScanner();
    ~LinuxScanner();

    bool SearchForHookAddress(const std::string& execPath, ScanResult& result);

private:
    std::vector<uint8_t> fileBuffer_;

    struct SectionInfo {
        uintptr_t va = 0;
        uintptr_t offset = 0;
        size_t size = 0;
        const uint8_t* data = nullptr;
    };

    bool LoadFile(const std::string& path);
    bool GetSectionByName(const char* name, SectionInfo& outSec);
    uintptr_t FindStringInRodata(const SectionInfo& rodata, const char* str);
    std::vector<uintptr_t> FindLeaRsiXrefs(const SectionInfo& text, uintptr_t targetVA);
    // 从 startVA 向前回扫 0x500 找 55 41 57 函数头（Xkey 原值）。
    // 注：这是针对**间接推导出的那条 xref**（实测距函数头仅 0x85 字节）够用的窗口；
    // 直接引用 cipher 配置名的那条 xref 距其函数头 0x697 字节，不在本锚点路径上。
    uintptr_t ScanBackwardsForPrologue(const SectionInfo& text, uintptr_t startVA);
};