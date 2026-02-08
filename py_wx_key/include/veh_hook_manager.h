#ifndef VEH_HOOK_MANAGER_H
#define VEH_HOOK_MANAGER_H

#include <Windows.h>
#include <functional>
#include <vector>
#include <unordered_map>

// 硬件断点 + VEH 管理（当前进程，多线程遍历）
class VehHookManager {
public:
    VehHookManager();
    ~VehHookManager();

    // 安装硬件断点并注册VEH
    bool Install(uintptr_t address, std::function<void(EXCEPTION_POINTERS*)> callback);
    // 卸载
    void Uninstall();

private:
    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* info);
    bool SetHardwareBreakpoint(uintptr_t address);
    void ClearHardwareBreakpoint();

    uintptr_t targetAddress;
    void* vehHandle;
    std::function<void(EXCEPTION_POINTERS*)> userCallback;
    std::unordered_map<DWORD, CONTEXT> originalContexts;
    bool installed;
};

#endif // VEH_HOOK_MANAGER_H
