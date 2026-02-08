#include "../include/syscalls.h"
#include "../include/string_obfuscator.h"
#include <string>
#include <cstdint>
#include <array>
#include <strsafe.h>

// 静态成员初始化
bool IndirectSyscalls::initialized = false;
pNtOpenProcess IndirectSyscalls::fnNtOpenProcess = nullptr;
pNtReadVirtualMemory IndirectSyscalls::fnNtReadVirtualMemory = nullptr;
pNtWriteVirtualMemory IndirectSyscalls::fnNtWriteVirtualMemory = nullptr;
pNtAllocateVirtualMemory IndirectSyscalls::fnNtAllocateVirtualMemory = nullptr;
pNtFreeVirtualMemory IndirectSyscalls::fnNtFreeVirtualMemory = nullptr;
pNtProtectVirtualMemory IndirectSyscalls::fnNtProtectVirtualMemory = nullptr;
pNtQueryInformationProcess IndirectSyscalls::fnNtQueryInformationProcess = nullptr;
// 直调stub
pNtOpenProcess IndirectSyscalls::scNtOpenProcess = nullptr;
pNtReadVirtualMemory IndirectSyscalls::scNtReadVirtualMemory = nullptr;
pNtWriteVirtualMemory IndirectSyscalls::scNtWriteVirtualMemory = nullptr;
pNtAllocateVirtualMemory IndirectSyscalls::scNtAllocateVirtualMemory = nullptr;
pNtFreeVirtualMemory IndirectSyscalls::scNtFreeVirtualMemory = nullptr;
pNtProtectVirtualMemory IndirectSyscalls::scNtProtectVirtualMemory = nullptr;
pNtQueryInformationProcess IndirectSyscalls::scNtQueryInformationProcess = nullptr;

template<typename T>
bool IndirectSyscalls::ResolveFunction(const char* functionName, T& functionPointer) {
    std::string ntdllName = ObfuscatedStrings::GetNtdllName();
    HMODULE hNtdll = GetModuleHandleA(ntdllName.c_str());
    if (!hNtdll) {
        return false;
    }
    
    functionPointer = reinterpret_cast<T>(GetProcAddress(hNtdll, functionName));
    return (functionPointer != nullptr);
}

namespace {
    // 标准 stub 前缀：mov r10, rcx; mov eax, imm32; syscall; ret
    bool LooksLikePatchedStub(void* fn) {
        if (!fn) return true;
        const uint8_t* code = reinterpret_cast<const uint8_t*>(fn);
        // 4C 8B D1 B8 xx xx xx xx 0F 05 C3
        constexpr std::array<uint8_t, 3> kPrefix = {0x4C, 0x8B, 0xD1};
        for (size_t i = 0; i < kPrefix.size(); ++i) {
            if (code[i] != kPrefix[i]) {
                return true;
            }
        }
        return false;
    }

    FARPROC LoadCleanNtdllFunction(const char* functionName) {
        wchar_t sysDir[MAX_PATH]{};
        if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) {
            return nullptr;
        }

        wchar_t ntdllPath[MAX_PATH]{};
        if (FAILED(StringCchPrintfW(ntdllPath, MAX_PATH, L"%s\\ntdll.dll", sysDir))) {
            return nullptr;
        }

        HMODULE hNtdll = LoadLibraryExW(
            ntdllPath,
            nullptr,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_SEARCH_SYSTEM32
        );
        if (!hNtdll) {
            return nullptr;
        }

        FARPROC fn = GetProcAddress(hNtdll, functionName);
        FreeLibrary(hNtdll);
        return fn;
    }

    void* ChooseSyscallSource(const char* functionName) {
        void* fn = reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA(ObfuscatedStrings::GetNtdllName().c_str()), functionName));
        if (fn && !LooksLikePatchedStub(fn)) {
            return fn;
        }

        FARPROC clean = LoadCleanNtdllFunction(functionName);
        if (clean) {
            return reinterpret_cast<void*>(clean);
        }
        return fn;
    }
} // namespace

bool IndirectSyscalls::Initialize() {
    if (initialized) {
        return true;
    }
    
    bool success = true;
    success &= ResolveFunction("NtOpenProcess", fnNtOpenProcess);
    success &= ResolveFunction("NtReadVirtualMemory", fnNtReadVirtualMemory);
    success &= ResolveFunction("NtWriteVirtualMemory", fnNtWriteVirtualMemory);
    success &= ResolveFunction("NtAllocateVirtualMemory", fnNtAllocateVirtualMemory);
    success &= ResolveFunction("NtFreeVirtualMemory", fnNtFreeVirtualMemory);
    success &= ResolveFunction("NtProtectVirtualMemory", fnNtProtectVirtualMemory);
    success &= ResolveFunction("NtQueryInformationProcess", fnNtQueryInformationProcess);

    // 构建直调 stub，必要时使用干净的 ntdll 提取 SSN
    scNtOpenProcess = reinterpret_cast<pNtOpenProcess>(CreateSyscallStub(ExtractSyscallNumber(ChooseSyscallSource("NtOpenProcess"))));
    scNtReadVirtualMemory = reinterpret_cast<pNtReadVirtualMemory>(CreateSyscallStub(ExtractSyscallNumber(ChooseSyscallSource("NtReadVirtualMemory"))));
    scNtWriteVirtualMemory = reinterpret_cast<pNtWriteVirtualMemory>(CreateSyscallStub(ExtractSyscallNumber(ChooseSyscallSource("NtWriteVirtualMemory"))));
    scNtAllocateVirtualMemory = reinterpret_cast<pNtAllocateVirtualMemory>(CreateSyscallStub(ExtractSyscallNumber(ChooseSyscallSource("NtAllocateVirtualMemory"))));
    scNtFreeVirtualMemory = reinterpret_cast<pNtFreeVirtualMemory>(CreateSyscallStub(ExtractSyscallNumber(ChooseSyscallSource("NtFreeVirtualMemory"))));
    scNtProtectVirtualMemory = reinterpret_cast<pNtProtectVirtualMemory>(CreateSyscallStub(ExtractSyscallNumber(ChooseSyscallSource("NtProtectVirtualMemory"))));
    scNtQueryInformationProcess = reinterpret_cast<pNtQueryInformationProcess>(CreateSyscallStub(ExtractSyscallNumber(ChooseSyscallSource("NtQueryInformationProcess"))));

    initialized = success;
    return success;
}

void IndirectSyscalls::Cleanup() {
    // 清理资源
    initialized = false;
}

NTSTATUS IndirectSyscalls::NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PMY_OBJECT_ATTRIBUTES ObjectAttributes,
    PMY_CLIENT_ID ClientId
) {
    if (!initialized || !fnNtOpenProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    if (scNtOpenProcess) {
        return scNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    return fnNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS IndirectSyscalls::NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
) {
    if (!initialized || !fnNtReadVirtualMemory) {
        return STATUS_UNSUCCESSFUL;
    }
    if (scNtReadVirtualMemory) {
        return scNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    }
    return fnNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS IndirectSyscalls::NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
) {
    if (!initialized || !fnNtWriteVirtualMemory) {
        return STATUS_UNSUCCESSFUL;
    }
    if (scNtWriteVirtualMemory) {
        return scNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }
    return fnNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS IndirectSyscalls::NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    if (!initialized || !fnNtAllocateVirtualMemory) {
        return STATUS_UNSUCCESSFUL;
    }
    if (scNtAllocateVirtualMemory) {
        return scNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }
    return fnNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS IndirectSyscalls::NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) {
    if (!initialized || !fnNtFreeVirtualMemory) {
        return STATUS_UNSUCCESSFUL;
    }
    if (scNtFreeVirtualMemory) {
        return scNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    }
    return fnNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS IndirectSyscalls::NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    if (!initialized || !fnNtProtectVirtualMemory) {
        return STATUS_UNSUCCESSFUL;
    }
    if (scNtProtectVirtualMemory) {
        return scNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }
    return fnNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS IndirectSyscalls::NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
) {
    if (!initialized || !fnNtQueryInformationProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    if (scNtQueryInformationProcess) {
        return scNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    }
    return fnNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

uint32_t IndirectSyscalls::ExtractSyscallNumber(void* fnAddress) {
    if (!fnAddress) {
        return UINT32_MAX;
    }
    const uint8_t* code = reinterpret_cast<const uint8_t*>(fnAddress);
    // 扫描前24字节，寻找 mov eax, imm32
    for (size_t i = 0; i < 24; ++i) {
        if (code[i] == 0xB8 && i + 4 < 24) { // mov eax, imm32
            uint32_t ssn = *reinterpret_cast<const uint32_t*>(code + i + 1);
            return ssn;
        }
    }
    return UINT32_MAX;
}

void* IndirectSyscalls::CreateSyscallStub(uint32_t ssn) {
    if (ssn == UINT32_MAX) {
        return nullptr;
    }

    // mov r10, rcx; mov eax, ssn; syscall; ret
    uint8_t stubTemplate[] = {
        0x4C, 0x8B, 0xD1,       // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, ssn
        0x0F, 0x05,             // syscall
        0xC3                    // ret
    };

    stubTemplate[4] = (uint8_t)(ssn & 0xFF);
    stubTemplate[5] = (uint8_t)((ssn >> 8) & 0xFF);
    stubTemplate[6] = (uint8_t)((ssn >> 16) & 0xFF);
    stubTemplate[7] = (uint8_t)((ssn >> 24) & 0xFF);

    void* mem = VirtualAlloc(nullptr, sizeof(stubTemplate), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        return nullptr;
    }
    memcpy(mem, stubTemplate, sizeof(stubTemplate));
    DWORD oldProt = 0;
    VirtualProtect(mem, sizeof(stubTemplate), PAGE_EXECUTE_READ, &oldProt);
    return mem;
}

