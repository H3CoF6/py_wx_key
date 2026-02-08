#ifndef REMOTE_HOOKER_H
#define REMOTE_HOOKER_H

#include <Windows.h>
#include <vector>
#include "shellcode_builder.h"
#include "remote_memory.h"

// 远程Hook管理器
class RemoteHooker {
public:
    RemoteHooker(HANDLE hProcess);
    ~RemoteHooker();
    void EnableHardwareBreakpointMode(bool enabled) { useHardwareBreakpoint = enabled; }
    
    /**
     * 安装远程Hook
     * @param targetFunctionAddress 目标函数地址
     * @param shellcodeConfig Shellcode配置
     * @return 成功返回true
     */
    bool InstallHook(uintptr_t targetFunctionAddress, const ShellcodeConfig& shellcodeConfig);
    
    /**
     * 卸载Hook
     * @return 成功返回true
     */
    bool UninstallHook();
    
    /**
     * 获取Trampoline地址（用于Shellcode配置）
     * @return Trampoline地址
     */
    uintptr_t GetTrampolineAddress() const { return trampolineAddress; }

    /**
     * 获取远程Shellcode地址（供VEH模式使用）
     */
    uintptr_t GetRemoteShellcodeAddress() const { return remoteShellcodeAddress; }
    
private:
    HANDLE hProcess;
    
    // Hook相关状态
    uintptr_t targetAddress;
    uintptr_t remoteShellcodeAddress;
    uintptr_t trampolineAddress;
    std::vector<BYTE> originalBytes;
    bool isHookInstalled;
    bool useHardwareBreakpoint{false};
    RemoteMemory trampolineMemory;
    RemoteMemory shellcodeMemory;
    
    // 在远程进程分配内存
    PVOID RemoteAllocate(SIZE_T size, DWORD protect);
    
    // 读取/写入/保护
    bool RemoteWrite(PVOID address, const void* data, SIZE_T size);
    bool RemoteRead(PVOID address, void* buffer, SIZE_T size);
    bool RemoteProtect(PVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect);
    
    // 创建Trampoline（保存原始指令）
    bool CreateTrampoline(uintptr_t targetAddress);
    
    // 计算需要备份的指令长度
    size_t CalculateHookLength(const BYTE* code);
    
    // 生成跳转指令（5字节短跳转或14字节长跳转）
    std::vector<BYTE> GenerateJumpInstruction(uintptr_t from, uintptr_t to);
};

#endif // REMOTE_HOOKER_H
