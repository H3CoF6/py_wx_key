#ifndef SHELLCODE_BUILDER_H
#define SHELLCODE_BUILDER_H

#include <Windows.h>
#include <vector>
#include <string>

// Shellcode配置
struct ShellcodeConfig {
    PVOID sharedMemoryAddress;  // 共享内存地址
    HANDLE eventHandle;         // 事件句柄
    uintptr_t trampolineAddress; // Trampoline地址（原始函数继续执行的地址）
    bool enableStackSpoofing{false}; // 是否启用堆栈伪造
    uintptr_t spoofStackPointer{0};  // 伪造栈指针（指向伪栈顶）
};

// Shellcode构建器
class ShellcodeBuilder {
public:
    ShellcodeBuilder();
    ~ShellcodeBuilder();
    
    // 构建Hook Shellcode
    std::vector<BYTE> BuildHookShellcode(const ShellcodeConfig& config);
    
    // 获取Shellcode大小
    size_t GetShellcodeSize() const;
    
private:
    std::vector<BYTE> shellcode;
    
    // 清除Shellcode
    void Clear();
};

#endif // SHELLCODE_BUILDER_H

