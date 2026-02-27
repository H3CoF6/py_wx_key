#ifndef SHELLCODE_BUILDER_H
#define SHELLCODE_BUILDER_H

#include <Windows.h>
#include <vector>
#include <string>

enum class HookType {
    DB_KEY,
    MD5
};

// Shellcode配置
struct ShellcodeConfig {
    PVOID sharedMemoryAddress;
    HANDLE eventHandle;
    uintptr_t trampolineAddress;
    bool enableStackSpoofing{ false };
    uintptr_t spoofStackPointer{ 0 };
    HookType type{ HookType::DB_KEY }; 
};

// Shellcode构建器
class ShellcodeBuilder {
public:
    ShellcodeBuilder();
    ~ShellcodeBuilder();
    
    // 构建Hook Shellcode
    std::vector<BYTE> BuildHookShellcode(const ShellcodeConfig& config);
    std::vector<BYTE> BuildMd5HookShellcode(const ShellcodeConfig& config);
    
    // 获取Shellcode大小
    size_t GetShellcodeSize() const;
    
private:
    std::vector<BYTE> shellcode;
    
    // 清除Shellcode
    void Clear();
};

#endif // SHELLCODE_BUILDER_H

