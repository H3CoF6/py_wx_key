#include "../include/veh_hook_manager.h"
#include <TlHelp32.h>
#include <vector>

namespace {
    VehHookManager* g_instance = nullptr;
}

VehHookManager::VehHookManager()
    : targetAddress(0)
    , vehHandle(nullptr)
    , installed(false) {
}

VehHookManager::~VehHookManager() {
    Uninstall();
}

bool VehHookManager::SetHardwareBreakpoint(uintptr_t address) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    std::vector<std::pair<DWORD, HANDLE>> threads;

    if (Thread32First(snapshot, &te)) {
        DWORD currentPid = GetCurrentProcessId();
        do {
            if (te.th32OwnerProcessID == currentPid) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    threads.emplace_back(te.th32ThreadID, hThread);
                }
            }
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);

    bool ok = true;
    for (const auto& entry : threads) {
        DWORD threadId = entry.first;
        HANDLE hThread = entry.second;
        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(hThread, &ctx)) {
            ok = false;
            CloseHandle(hThread);
            continue;
        }

        originalContexts[threadId] = ctx; // 保存每个线程的原始状态
        ctx.Dr0 = address;
        ctx.Dr7 |= 0x1; // 启用 DR0 全局断点

        if (!SetThreadContext(hThread, &ctx)) {
            ok = false;
        }
        CloseHandle(hThread);
    }
    return ok;
}

void VehHookManager::ClearHardwareBreakpoint() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snapshot, &te)) {
        DWORD currentPid = GetCurrentProcessId();
        do {
            if (te.th32OwnerProcessID == currentPid) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    CONTEXT ctx{};
                    auto it = originalContexts.find(te.th32ThreadID);
                    if (it != originalContexts.end()) {
                        ctx = it->second;
                    } else {
                        ZeroMemory(&ctx, sizeof(ctx));
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    }
                    ctx.Dr0 = 0;
                    ctx.Dr7 = 0;
                    SetThreadContext(hThread, &ctx);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);
}

bool VehHookManager::Install(uintptr_t address, std::function<void(EXCEPTION_POINTERS*)> callback) {
    if (installed) {
        return false;
    }

    targetAddress = address;
    userCallback = std::move(callback);

    if (!SetHardwareBreakpoint(targetAddress)) {
        return false;
    }

    vehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!vehHandle) {
        ClearHardwareBreakpoint();
        return false;
    }

    g_instance = this;
    installed = true;
    return true;
}

void VehHookManager::Uninstall() {
    if (!installed) {
        return;
    }

    ClearHardwareBreakpoint();

    if (vehHandle) {
        RemoveVectoredExceptionHandler(vehHandle);
        vehHandle = nullptr;
    }

    originalContexts.clear();
    installed = false;
    g_instance = nullptr;
}

LONG CALLBACK VehHookManager::VectoredHandler(EXCEPTION_POINTERS* info) {
    if (!g_instance || info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (info->ContextRecord->Rip == g_instance->targetAddress) {
        if (g_instance->userCallback) {
            g_instance->userCallback(info);
        }
        // 清除单步标志，继续执行
        info->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
