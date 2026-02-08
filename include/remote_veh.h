#ifndef REMOTE_VEH_H
#define REMOTE_VEH_H

#include <Windows.h>
#include <functional>
#include "remote_memory.h"

struct RemoteVehConfig {
    HANDLE hProcess;
    uintptr_t targetAddress;
    uintptr_t shellcodeAddress;
};

// 工具：在远程进程注册VEH，并为所有线程设置硬件断点
// 返回句柄和用于卸载的必要信息
struct RemoteVehHandle {
    PVOID vehHandle;
    PVOID handlerCode;
    PVOID dataBlock;
    uintptr_t unregStubAddress;
    RemoteMemory remoteMemory;
    bool installed;
};

RemoteVehHandle InstallRemoteVeh(const RemoteVehConfig& cfg);
void UninstallRemoteVeh(const RemoteVehConfig& cfg, RemoteVehHandle& handle);

#endif // REMOTE_VEH_H
