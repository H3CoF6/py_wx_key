#include <Windows.h>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <memory>
#include <vector>

#include "../include/hook_controller.h"
#include "../include/syscalls.h"
#include "../include/remote_scanner.h"
#include "../include/ipc_manager.h"
#include "../include/remote_hooker.h"
#include "../include/shellcode_builder.h"
#include "../include/string_obfuscator.h"
#include "../include/remote_veh.h"
#include "../include/remote_memory.h"

#pragma execution_character_set("utf-8")

// 全局状态
namespace {
    bool InitializeContext(DWORD targetPid, const char* version, const char* pattern, const char* mask, int offset);
    void CleanupContext();
    struct StatusMessage {
        std::string message;
        int level;
    };

    struct HookContext {
        HANDLE hProcess{ nullptr };
        std::unique_ptr<IPCManager> ipc;
        std::unique_ptr<RemoteHooker> keyHooker;   // 改名
        std::unique_ptr<RemoteHooker> md5Hooker;
        RemoteMemory remoteData;
        RemoteMemory spoofStack;
        CRITICAL_SECTION dataLock{};
        bool csInitialized{ false };
        std::string pendingKeyData;
        std::string pendingMd5Data;
        bool hasNewKey{ false };
        bool hasNewMd5{ false };
        std::vector<StatusMessage> statusQueue;
        bool initialized{ false };

        void InitLock() {
            if (!csInitialized) {
                InitializeCriticalSection(&dataLock);
                csInitialized = true;
            }
        }

        void FreeLock() {
            if (csInitialized) {
                DeleteCriticalSection(&dataLock);
                csInitialized = false;
            }
        }

        void ResetDataQueues() {
            pendingKeyData.clear();
			pendingMd5Data.clear();
			hasNewMd5 = false;
            hasNewKey = false;
            statusQueue.clear();
        }
    };

    HookContext g_ctx;
    std::string g_lastError;

    std::string WideToUtf8(const std::wstring& wide) {
        if (wide.empty()) return std::string();
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0) return std::string();
        std::string utf8(sizeNeeded, 0);
        WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), reinterpret_cast<LPSTR>(&utf8[0]), sizeNeeded, nullptr, nullptr);
        return utf8;
    }
    
    std::string GenerateUniqueId(DWORD pid) {
        std::stringstream ss;
        ss << std::hex << pid << "_" << GetTickCount64();
        return ss.str();
    }

    void SendStatus(const std::string& message, int level) {
        if (g_ctx.csInitialized) EnterCriticalSection(&g_ctx.dataLock);
        g_ctx.statusQueue.push_back({message, level});
        if (g_ctx.statusQueue.size() > 100) g_ctx.statusQueue.erase(g_ctx.statusQueue.begin());
        if (g_ctx.csInitialized) LeaveCriticalSection(&g_ctx.dataLock);
    }
    
    std::string GetSystemErrorMessage(DWORD errorCode) {
        if (errorCode == 0) return std::string();
        LPWSTR buffer = nullptr;
        DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
        std::string message;
        if (length && buffer) {
            std::wstring wideMessage(buffer, length);
            while (!wideMessage.empty() && (wideMessage.back() == L'\r' || wideMessage.back() == L'\n')) wideMessage.pop_back();
            message = WideToUtf8(wideMessage);
        }
        if (buffer) LocalFree(buffer);
        return message;
    }

    std::string FormatWin32Error(const std::string& baseMessage, DWORD errorCode) {
        std::ostringstream oss;
        oss << baseMessage;
        if (errorCode != 0) {
            oss << " (code " << errorCode << ")";
            std::string detail = GetSystemErrorMessage(errorCode);
            if (!detail.empty()) oss << ": " << detail;
        }
        return oss.str();
    }

    std::string FormatNtStatusError(const std::string& baseMessage, NTSTATUS status) {
        std::ostringstream oss;
        oss << baseMessage << " (NTSTATUS 0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << static_cast<unsigned long>(status) << ")";
        return oss.str();
    }

    void SetLastError(const std::string& error) {
        g_lastError = error;
        SendStatus(error, 2);
    }

    void OnDataReceived(const SharedKeyData& data) {
        bool updated = false;
        if (g_ctx.csInitialized) EnterCriticalSection(&g_ctx.dataLock);

        if (data.dataSize == 32) {
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (DWORD i = 0; i < data.dataSize; i++) ss << std::setw(2) << static_cast<int>(data.keyBuffer[i]);
            g_ctx.pendingKeyData = ss.str();
            g_ctx.hasNewKey = true;
            updated = true;
        }

        if (data.md5Size == 32) {
            std::string md5Str(reinterpret_cast<const char*>(data.md5Buffer), 32);
            g_ctx.pendingMd5Data = md5Str;
            g_ctx.hasNewMd5 = true;
            updated = true;
        }

        if (g_ctx.csInitialized) LeaveCriticalSection(&g_ctx.dataLock);
        if (updated) SendStatus("已成功接收到Hook数据", 1);
    }
}

    std::vector<BYTE> HexStringToBytes(const std::string& hex) {
        std::vector<BYTE> bytes;
        std::string cleanHex;
        for (char c : hex) {
            if (isxdigit(c)) cleanHex += c;
        }
        for (size_t i = 0; i + 1 < cleanHex.length(); i += 2) {
            std::string byteString = cleanHex.substr(i, 2);
            BYTE byte = (BYTE)strtol(byteString.c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }
}

namespace {
    bool InitializeContext(
        DWORD targetPid, const char* version,
        const char* keyPattern, const char* keyMask, int keyOffset,
        const char* md5Pattern, const char* md5Mask, int md5Offset) {

        if (g_ctx.initialized) {
            SetLastError("Hook已经初始化");
            return false;
        }

        g_ctx.InitLock();
        g_ctx.ResetDataQueues();
        SendStatus("开始初始化Hook系统...", 0);

        // 1. 初始化系统调用
        if (!IndirectSyscalls::Initialize()) {
            SetLastError(FormatWin32Error("初始化间接系统调用失败", GetLastError()));
            g_ctx.FreeLock();
            return false;
        }

        // 2. 打开进程
        MY_OBJECT_ATTRIBUTES objAttr = { sizeof(MY_OBJECT_ATTRIBUTES) };
        MY_CLIENT_ID clientId = { (PVOID)(ULONG_PTR)targetPid, 0 };
        HANDLE hProcess = NULL;
        NTSTATUS status = IndirectSyscalls::NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
        g_ctx.hProcess = hProcess;
        if (status != STATUS_SUCCESS || !g_ctx.hProcess) {
            SetLastError(FormatNtStatusError("打开目标进程失败", status));
            CleanupContext();
            return false;
        }

        RemoteScanner scanner(g_ctx.hProcess);

        // 3. 微信版本校验 (可选)
        if (version && strlen(version) > 0) {
            SendStatus("正在检测微信版本...", 0);
            std::string wechatVersion = scanner.GetWeChatVersion();
            if (wechatVersion.empty()) {
                SetLastError("获取微信版本失败");
                CleanupContext();
                return false;
            }
            SendStatus("检测到的微信版本: " + wechatVersion, 0);
            if (wechatVersion != version) {
                SetLastError("微信版本不匹配，期望: " + std::string(version) + "，实际: " + wechatVersion);
                CleanupContext();
                return false;
            }
        }

        // 4. 扫描函数
        SendStatus("正在扫描目标函数...", 0);
        std::string weixinDll = ObfuscatedStrings::GetWeixinDllName();
        RemoteModuleInfo moduleInfo;
        if (!scanner.GetRemoteModuleInfo(weixinDll, moduleInfo)) {
            SetLastError("未找到Weixin.dll模块");
            CleanupContext();
            return false;
        }

        std::vector<BYTE> keyPatternBytes = HexStringToBytes(keyPattern);
        std::vector<uintptr_t> keyResults = scanner.FindAllPatterns(moduleInfo, keyPatternBytes.data(), keyMask);
        if (keyResults.size() != 1) {
            SetLastError("DB Key 特征码匹配失败");
            CleanupContext(); return false;
        }
        uintptr_t keyAddress = keyResults[0] + keyOffset;

        // --- 获取 MD5 Call 地址并动态越过 NOP ---
        std::vector<BYTE> md5PatternBytes = HexStringToBytes(md5Pattern);
        std::vector<uintptr_t> md5Results = scanner.FindAllPatterns(moduleInfo, md5PatternBytes.data(), md5Mask);
        if (md5Results.size() != 1) {
            SetLastError("MD5 特征码匹配失败");
            CleanupContext(); return false;
        }

        uintptr_t md5CallAddr = md5Results[0] + md5Offset;
        BYTE callOp = 0;
        scanner.ReadRemoteMemory(md5CallAddr, &callOp, 1);
        if (callOp != 0xE8) {
            SetLastError("MD5特征定位的指令不是 CALL (0xE8)");
            CleanupContext(); return false;
        }

        // 定位到 CALL 执行完的下一条指令
        uintptr_t md5HookAddress = md5CallAddr + 5;
        BYTE nextOp = 0;
        scanner.ReadRemoteMemory(md5HookAddress, &nextOp, 1);
        if (nextOp == 0x90) { // 动态适配 NOP 对齐
            md5HookAddress += 1;
            SendStatus("检测到 90 NOP 填充，已自动修正 MD5 Hook 地址", 0);
        }

        // 5. 分配远程资源
        if (!g_ctx.remoteData.allocate(g_ctx.hProcess, sizeof(SharedKeyData), PAGE_READWRITE)) {
            SetLastError("分配远程数据缓冲区失败");
            CleanupContext();
            return false;
        }

        const SIZE_T spoofStackSize = 0x8000;
        if (!g_ctx.spoofStack.allocate(g_ctx.hProcess, spoofStackSize, PAGE_READWRITE)) {
            SetLastError("分配远程伪栈失败");
            CleanupContext();
            return false;
        }
        uintptr_t spoofStackTop = reinterpret_cast<uintptr_t>(g_ctx.spoofStack.get()) + spoofStackSize - 0x20;

        // 6. 初始化IPC
        std::string uniqueId = GenerateUniqueId(targetPid);
        g_ctx.ipc = std::make_unique<IPCManager>();
        if (!g_ctx.ipc->Initialize(uniqueId)) {
            SetLastError(FormatWin32Error("初始化IPC通信失败", GetLastError()));
            CleanupContext();
            return false;
        }
        g_ctx.ipc->SetRemoteBuffer(g_ctx.hProcess, g_ctx.remoteData.get());
        g_ctx.ipc->SetDataCallback(OnDataReceived);
        if (!g_ctx.ipc->StartListening()) {
            SetLastError(FormatWin32Error("启动IPC监听失败", GetLastError()));
            CleanupContext();
            return false;
        }

        // --- 安装 DB Key Hook ---
        g_ctx.keyHooker = std::make_unique<RemoteHooker>(g_ctx.hProcess);
        ShellcodeConfig keyConfig{};
        keyConfig.sharedMemoryAddress = g_ctx.remoteData.get();
        keyConfig.enableStackSpoofing = true;
        keyConfig.spoofStackPointer = spoofStackTop;
        keyConfig.type = HookType::DB_KEY;
        if (!g_ctx.keyHooker->InstallHook(keyAddress, keyConfig)) {
            SetLastError("安装 DB Key Hook 失败");
            CleanupContext(); return false;
        }

        // --- 安装 MD5 Hook ---
        g_ctx.md5Hooker = std::make_unique<RemoteHooker>(g_ctx.hProcess);
        ShellcodeConfig md5Config = keyConfig;
        md5Config.type = HookType::MD5;
        md5Config.spoofStackPointer = spoofStackTop - 0x1000; // 为第二个Hook分配另一块伪栈区域

        if (!g_ctx.md5Hooker->InstallHook(md5HookAddress, md5Config)) {
            SetLastError("安装 MD5 Hook 失败");
            CleanupContext(); return false;
        }

        g_ctx.initialized = true;
        SendStatus("双 Hook 安装成功", 1);
        return true;
    }
}

    void CleanupContext() {
        if (g_ctx.hooker) { g_ctx.hooker->UninstallHook(); g_ctx.hooker.reset(); }
        if (g_ctx.ipc) { g_ctx.ipc->StopListening(); g_ctx.ipc->Cleanup(); g_ctx.ipc.reset(); }
        g_ctx.remoteData.reset();
        g_ctx.spoofStack.reset();
        if (g_ctx.hProcess) { CloseHandle(g_ctx.hProcess); g_ctx.hProcess = nullptr; }
        IndirectSyscalls::Cleanup();
        if (g_ctx.csInitialized) {
            EnterCriticalSection(&g_ctx.dataLock);
            g_ctx.ResetDataQueues();
            LeaveCriticalSection(&g_ctx.dataLock);
            g_ctx.FreeLock();
        }
        g_ctx.initialized = false;
    }
}

HOOK_API bool InitializeHook(DWORD targetPid, const char* version, const char* pattern, const char* mask, int offset) {
    return InitializeContext(targetPid, version, pattern, mask, offset);
}

HOOK_API bool CleanupHook() {
    if (!g_ctx.initialized) return true;
    CleanupContext();
    return true;
}

HOOK_API bool PollKeyData(char* keyBuffer, int keyBufferSize, char* md5Buffer, int md5BufferSize) {
    if (!g_ctx.initialized) return false;
    if (g_ctx.csInitialized) EnterCriticalSection(&g_ctx.dataLock);

    bool hasAnyData = false;

    if (keyBuffer && keyBufferSize > 0) keyBuffer[0] = '\0';
    if (md5Buffer && md5BufferSize > 0) md5Buffer[0] = '\0';

    if (g_ctx.hasNewKey && keyBuffer && keyBufferSize >= 65) {
        size_t len = min(g_ctx.pendingKeyData.length(), (size_t)keyBufferSize - 1);
        memcpy(keyBuffer, g_ctx.pendingKeyData.c_str(), len);
        keyBuffer[len] = '\0';
        g_ctx.hasNewKey = false;
        hasAnyData = true;
    }

    if (g_ctx.hasNewMd5 && md5Buffer && md5BufferSize >= 33) {
        size_t len = min(g_ctx.pendingMd5Data.length(), (size_t)md5BufferSize - 1);
        memcpy(md5Buffer, g_ctx.pendingMd5Data.c_str(), len);
        md5Buffer[len] = '\0';
        g_ctx.hasNewMd5 = false;
        hasAnyData = true;
    }

    if (g_ctx.csInitialized) LeaveCriticalSection(&g_ctx.dataLock);
    return hasAnyData;
}

HOOK_API bool GetStatusMessage(char* statusBuffer, int bufferSize, int* outLevel) {
    if (!g_ctx.initialized || !statusBuffer || bufferSize < 256 || !outLevel) return false;
    if (g_ctx.csInitialized) EnterCriticalSection(&g_ctx.dataLock);
    if (g_ctx.statusQueue.empty()) {
        if (g_ctx.csInitialized) LeaveCriticalSection(&g_ctx.dataLock);
        return false;
    }
    StatusMessage msg = g_ctx.statusQueue.front();
    g_ctx.statusQueue.erase(g_ctx.statusQueue.begin());
    if (g_ctx.csInitialized) LeaveCriticalSection(&g_ctx.dataLock);
    size_t copyLen = (msg.message.length() < (size_t)bufferSize - 1) ? msg.message.length() : (size_t)bufferSize - 1;
    memcpy(statusBuffer, msg.message.c_str(), copyLen);
    statusBuffer[copyLen] = '\0';
    *outLevel = msg.level;
    return true;
}

HOOK_API const char* GetLastErrorMsg() {
    return g_lastError.c_str();
}
