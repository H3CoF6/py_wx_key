#include "../include/remote_veh.h"
#include "../include/syscalls.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>
#include <Psapi.h>
#include <cstdio>

namespace {
    constexpr SIZE_T RIP_OFFSET = offsetof(CONTEXT, Rip);
    constexpr SIZE_T EFLAGS_OFFSET = offsetof(CONTEXT, EFlags);

    struct RemoteData {
        uint64_t target;
        uint64_t shellcode;
        uint64_t vehHandle;
    };

    void DebugProtectChange(const char* label, void* address, SIZE_T size, DWORD protect) {
        char buffer[160]{};
        _snprintf_s(buffer, sizeof(buffer) - 1, _TRUNCATE, "[RemoteVEH] %s addr=%p size=%zu prot=0x%lx\n",
            label, address, static_cast<size_t>(size), static_cast<unsigned long>(protect));
        OutputDebugStringA(buffer);
    }

    bool SetHardwareBreakpointThread(HANDLE hProcess, DWORD tid, uintptr_t address) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (!hThread) return false;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        bool ok = false;
        if (GetThreadContext(hThread, &ctx)) {
            ctx.Dr0 = address;
            ctx.Dr7 |= 0x1;
            ok = SetThreadContext(hThread, &ctx) == TRUE;
        }
        CloseHandle(hThread);
        return ok;
    }

    bool SetHardwareBreakpointAllThreads(HANDLE hProcess, uintptr_t address) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        DWORD pid = GetProcessId(hProcess);
        bool ok = true;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    if (!SetHardwareBreakpointThread(hProcess, te.th32ThreadID, address)) {
                        ok = false;
                    }
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return ok;
    }

    void ClearHardwareBreakpointAllThreads(HANDLE hProcess) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        DWORD pid = GetProcessId(hProcess);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (GetThreadContext(hThread, &ctx)) {
                            ctx.Dr0 = 0;
                            ctx.Dr7 = 0;
                            SetThreadContext(hThread, &ctx);
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    uintptr_t GetRemoteProcAddress(HANDLE hProcess, const char* moduleName, FARPROC localProc) {
        if (!moduleName) {
            return 0;
        }

        HMODULE localMod = GetModuleHandleA(moduleName);
        if (!localMod || !localProc) return 0;
        uintptr_t localBase = reinterpret_cast<uintptr_t>(localMod);
        uintptr_t localAddr = reinterpret_cast<uintptr_t>(localProc);
        uintptr_t offset = localAddr - localBase;

        HMODULE hMods[512];
        DWORD cbNeeded = 0;
        if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            return 0;
        }
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i) {
            char modName[MAX_PATH]{};
            if (GetModuleBaseNameA(hProcess, hMods[i], modName, MAX_PATH)) {
                if (_stricmp(modName, moduleName) == 0) {
                    uintptr_t remoteBase = reinterpret_cast<uintptr_t>(hMods[i]);
                    return remoteBase + offset;
                }
            }
        }
        return 0;
    }

    bool BuildRemoteCode(HANDLE hProcess, uintptr_t target, uintptr_t shellcode, FARPROC addVeh, FARPROC removeVeh, RemoteVehHandle& outHandle) {
        std::vector<uint8_t> buf;
        buf.reserve(512);

        // data
        RemoteData localData{};
        localData.target = target;
        localData.shellcode = shellcode;
        localData.vehHandle = 0;
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&localData), reinterpret_cast<uint8_t*>(&localData) + sizeof(localData));

        auto emit = [&](std::initializer_list<uint8_t> bytes) {
            buf.insert(buf.end(), bytes.begin(), bytes.end());
        };

        auto emitDisp32 = [&](uint32_t disp) {
            emit({
                static_cast<uint8_t>(disp & 0xFF),
                static_cast<uint8_t>((disp >> 8) & 0xFF),
                static_cast<uint8_t>((disp >> 16) & 0xFF),
                static_cast<uint8_t>((disp >> 24) & 0xFF)
            });
        };

        // handler
        size_t handlerOffset = buf.size();
        emit({0x48,0x8B,0x01});                 // mov rax,[rcx] (ExceptionRecord)
        emit({0x8B,0x00});                      // mov eax,[rax] (ExceptionCode)
        emit({0x3D,0x04,0x00,0x00,0x80});       // cmp eax,0x80000004
        emit({0x75,0x2B});                      // jne cont
        emit({0x48,0x8B,0x51,0x08});            // mov rdx,[rcx+8] (Context)
        emit({0x48,0xB8}); size_t tgtPatch = buf.size(); buf.resize(buf.size()+8); // mov rax,target
        emit({0x48,0x3B,0x82}); emitDisp32(static_cast<uint32_t>(RIP_OFFSET)); // cmp rax,[rdx+RIP]
        emit({0x75,0x14});                      // jne cont
        emit({0x48,0xB8}); size_t shPatch = buf.size(); buf.resize(buf.size()+8);  // mov rax,shellcode
        emit({0x48,0x89,0x82}); emitDisp32(static_cast<uint32_t>(RIP_OFFSET)); // mov [rdx+RIP],rax
        emit({0x48,0x8B,0x82}); emitDisp32(static_cast<uint32_t>(EFLAGS_OFFSET)); // mov rax,[rdx+EFLAGS]
        emit({0x48,0x25,0xFF,0xFE,0xFF,0xFF}); // and rax,~0x100
        emit({0x48,0x89,0x82}); emitDisp32(static_cast<uint32_t>(EFLAGS_OFFSET)); // mov [rdx+EFLAGS],rax
        emit({0xB8,0xFF,0xFF,0xFF,0xFF});      // mov eax,-1
        emit({0xC3});                           // ret
        emit({0x33,0xC0});                      // xor eax,eax
        emit({0xC3});                           // ret

        // register stub
        size_t regOffset = buf.size();
        emit({0x48,0x83,0xEC,0x28});           // sub rsp,28h
        emit({0x48,0x31,0xC9});                // xor rcx,rcx
        emit({0x48,0x83,0xC1,0x01});           // inc rcx (FirstHandler)
        emit({0x48,0xBA}); size_t hPatch = buf.size(); buf.resize(buf.size()+8); // mov rdx,handler
        emit({0x48,0xB8}); size_t addPatch = buf.size(); buf.resize(buf.size()+8); // mov rax,AddVEH
        emit({0xFF,0xD0});                     // call rax
        emit({0x48,0xA3}); size_t storePatch = buf.size(); buf.resize(buf.size()+8); // mov [vehHandle], rax
        emit({0x48,0x83,0xC4,0x28});           // add rsp,28h
        emit({0xC3});                          // ret

        // unregister stub
        size_t unregOffset = buf.size();
        emit({0x48,0x83,0xEC,0x28});           // sub rsp,28h
        emit({0x48,0xA1}); size_t loadPatch = buf.size(); buf.resize(buf.size()+8); // mov rax,[vehHandle]
        emit({0x48,0x85,0xC0});                // test rax,rax
        emit({0x74,0x14});                     // je skip
        emit({0x48,0x89,0xC1});                // mov rcx,rax
        emit({0x48,0xB8}); size_t remPatch = buf.size(); buf.resize(buf.size()+8);  // mov rax,RemoveVEH
        emit({0xFF,0xD0});                     // call rax
        emit({0x48,0x83,0xC4,0x28});           // add rsp,28h
        emit({0xC3});                          // ret

        // allocate remote
        RemoteMemory remoteBlock;
        SIZE_T allocSize = buf.size();
        if (!remoteBlock.allocate(hProcess, allocSize, PAGE_READWRITE)) {
            return false;
        }

        uintptr_t base = reinterpret_cast<uintptr_t>(remoteBlock.get());
        uintptr_t handlerAddr = base + handlerOffset;
        uintptr_t regAddr = base + regOffset;
        uintptr_t unregAddr = base + unregOffset;
        uintptr_t vehHandleAddr = base + offsetof(RemoteData, vehHandle);

        // patches
        memcpy(buf.data() + tgtPatch, &target, sizeof(uint64_t));
        memcpy(buf.data() + shPatch, &shellcode, sizeof(uint64_t));
        memcpy(buf.data() + hPatch, &handlerAddr, sizeof(uint64_t));
        uint64_t addAddr = reinterpret_cast<uint64_t>(addVeh);
        memcpy(buf.data() + addPatch, &addAddr, sizeof(uint64_t));
        memcpy(buf.data() + storePatch, &vehHandleAddr, sizeof(uint64_t));
        memcpy(buf.data() + loadPatch, &vehHandleAddr, sizeof(uint64_t));
        uint64_t remAddr = reinterpret_cast<uint64_t>(removeVeh);
        memcpy(buf.data() + remPatch, &remAddr, sizeof(uint64_t));

        if (!WriteProcessMemory(hProcess, remoteBlock.get(), buf.data(), buf.size(), nullptr)) {
            return false;
        }

        // 切换为RX，避免长期RWX
        if (!remoteBlock.protect(PAGE_EXECUTE_READ)) {
            return false;
        }
        DebugProtectChange("veh block RX", remoteBlock.get(), allocSize, PAGE_EXECUTE_READ);

        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)regAddr, nullptr, 0, nullptr);
        if (!hThread) {
            return false;
        }
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);

        outHandle.remoteMemory = std::move(remoteBlock);
        outHandle.dataBlock = outHandle.remoteMemory.get();
        outHandle.unregStubAddress = unregAddr;
        outHandle.vehHandle = reinterpret_cast<PVOID>(vehHandleAddr); // store address for reference
        outHandle.installed = true;
        return true;
    }
}

RemoteVehHandle InstallRemoteVeh(const RemoteVehConfig& cfg) {
    RemoteVehHandle handle = {};
    if (!cfg.hProcess || cfg.targetAddress == 0 || cfg.shellcodeAddress == 0) {
        return handle;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        return handle;
    }
    FARPROC addVehLocal = GetProcAddress(hKernel32, "AddVectoredExceptionHandler");
    FARPROC removeVehLocal = GetProcAddress(hKernel32, "RemoveVectoredExceptionHandler");
    uintptr_t addVeh = GetRemoteProcAddress(cfg.hProcess, "kernel32.dll", addVehLocal);
    uintptr_t removeVeh = GetRemoteProcAddress(cfg.hProcess, "kernel32.dll", removeVehLocal);
    if (!addVeh || !removeVeh) {
        return handle;
    }

    if (!BuildRemoteCode(cfg.hProcess, cfg.targetAddress, cfg.shellcodeAddress, reinterpret_cast<FARPROC>(addVeh), reinterpret_cast<FARPROC>(removeVeh), handle)) {
        return handle;
    }

    // handler 注册完成后再设置硬件断点，避免未注册时命中异常
    if (!SetHardwareBreakpointAllThreads(cfg.hProcess, cfg.targetAddress)) {
        UninstallRemoteVeh(cfg, handle);
        RemoteVehHandle emptyHandle = {};
        return emptyHandle;
    }

    return handle;
}

void UninstallRemoteVeh(const RemoteVehConfig& cfg, RemoteVehHandle& handle) {
    ClearHardwareBreakpointAllThreads(cfg.hProcess);

    if (handle.installed && handle.dataBlock) {
        HANDLE hThread = CreateRemoteThread(cfg.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)handle.unregStubAddress, nullptr, 0, nullptr);
        if (hThread) {
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
        }
        handle.remoteMemory.reset();
        handle.dataBlock = nullptr;
    }
    handle.installed = false;
}
