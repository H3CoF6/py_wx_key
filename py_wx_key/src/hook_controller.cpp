#include <Windows.h>
#include <ShlObj.h>
#include <WinCrypt.h>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <memory>
#include <vector>
#include <regex>
#include <algorithm>

#include "../include/hook_controller.h"
#include "../include/syscalls.h"
#include "../include/remote_scanner.h"
#include "../include/ipc_manager.h"
#include "../include/remote_hooker.h"
#include "../include/shellcode_builder.h"
#include "../include/string_obfuscator.h"
#include "../include/remote_memory.h"

#pragma execution_character_set("utf-8")

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

// 全局状态
namespace {
    struct StatusMessage {
        std::string message;
        int level;
    };

    struct HookContext {
        HANDLE hProcess{ nullptr };
        std::unique_ptr<IPCManager> ipc;
        std::unique_ptr<RemoteHooker> keyHooker;
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
            hasNewKey = false;
            hasNewMd5 = false;
            statusQueue.clear();
        }
    };

    HookContext g_ctx;
    std::string g_lastError;

    // 前置声明
    void CleanupContext();

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
        g_ctx.statusQueue.push_back({ message, level });
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

    std::string CalculateMD5(const char* data, DWORD length) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string md5Str = "";
        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                if (CryptHashData(hHash, (const BYTE*)data, length, 0)) {
                    DWORD hashLen = 16;
                    BYTE buffer[16];
                    if (CryptGetHashParam(hHash, HP_HASHVAL, buffer, &hashLen, 0)) {
                        char hex[33];
                        for (int i = 0; i < 16; i++) {
                            sprintf_s(hex + i * 2, 33, "%02x", buffer[i]);
                        }
                        md5Str = hex;
                    }
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }
        return md5Str;
    }

    void OnDataReceived(const SharedKeyData& data) {
        bool updated = false;
        if (data.dataSize == 32) {
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (DWORD i = 0; i < data.dataSize; i++) ss << std::setw(2) << static_cast<int>(data.keyBuffer[i]);
            if (g_ctx.csInitialized) EnterCriticalSection(&g_ctx.dataLock);
            g_ctx.pendingKeyData = ss.str();
            g_ctx.hasNewKey = true;
            updated = true;
            if (g_ctx.csInitialized) LeaveCriticalSection(&g_ctx.dataLock);
        }
        
        if (data.md5Size == 64) {
            char rawStr[65] = { 0 };
            memcpy(rawStr, data.md5Buffer, 64);
            size_t actualLen = 0;
            while (actualLen < 64 && rawStr[actualLen] != '\0') actualLen++;
            if (actualLen > 0) {
                std::string md5Hash = CalculateMD5(rawStr, (DWORD)actualLen);
                unsigned long long deviceCode = 0;
                for (size_t i = 0; i < actualLen; i++) {
                    if (rawStr[i] >= '0' && rawStr[i] <= '9') deviceCode = deviceCode * 10 + (rawStr[i] - '0');
                    else break;
                }
                int xorKey = deviceCode & 0xFF;
                std::string resultData = md5Hash.substr(0, 16) + "|" + std::to_string(xorKey);
                if (g_ctx.csInitialized) EnterCriticalSection(&g_ctx.dataLock);
                g_ctx.pendingMd5Data = resultData;
                g_ctx.hasNewMd5 = true;
                updated = true;
                if (g_ctx.csInitialized) LeaveCriticalSection(&g_ctx.dataLock);
            }
        }
        if (updated) SendStatus("已成功接收到Hook数据", 1);
    }

    std::vector<BYTE> HexStringToBytes(const std::string& hex) {
        std::vector<BYTE> bytes;
        std::string cleanHex;
        for (char c : hex) if (isxdigit(c)) cleanHex += c;
        for (size_t i = 0; i + 1 < cleanHex.length(); i += 2) {
            bytes.push_back((BYTE)strtol(cleanHex.substr(i, 2).c_str(), nullptr, 16));
        }
        return bytes;
    }

    void CleanupContext() {
        if (g_ctx.keyHooker) { g_ctx.keyHooker->UninstallHook(); g_ctx.keyHooker.reset(); }
        if (g_ctx.md5Hooker) { g_ctx.md5Hooker->UninstallHook(); g_ctx.md5Hooker.reset(); }
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

HOOK_API bool InitializeHook(DWORD targetPid, const char* md5Pattern, const char* md5Mask, int md5Offset) {
    if (g_ctx.initialized) {
        SetLastError("Hook已经初始化");
        return false;
    }

    g_ctx.InitLock();
    g_ctx.ResetDataQueues();
    SendStatus("开始初始化Hook系统...", 0);

    // 检查管理员权限
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            if (!elevation.TokenIsElevated) {
                SendStatus("[警告] 当前进程未以管理员权限运行，Hook 初始化可能会失败。", 1);
            }
        }
        CloseHandle(hToken);
    }

    if (!IndirectSyscalls::Initialize()) {
        SetLastError(FormatWin32Error("初始化间接系统调用失败", GetLastError()));
        g_ctx.FreeLock();
        return false;
    }

    MY_OBJECT_ATTRIBUTES objAttr = { 0 }; // 完整置零
    objAttr.Length = sizeof(MY_OBJECT_ATTRIBUTES);
    MY_CLIENT_ID clientId = { (PVOID)(ULONG_PTR)targetPid, 0 };
    HANDLE hProcess = NULL;
    NTSTATUS status = IndirectSyscalls::NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    g_ctx.hProcess = hProcess;
    if (status != STATUS_SUCCESS || !g_ctx.hProcess) {
        std::string errMsg = "打开目标进程失败 (PID: " + std::to_string(targetPid) + ")";
        SetLastError(FormatNtStatusError(errMsg, status));
        CleanupContext();
        return false;
    }

    // 1. 自动扫描 DB Key Hook 地址
    RemoteScanner scanner(g_ctx.hProcess);
    ScanResult dbResult;
    if (!scanner.SearchForHookAddress(dbResult)) {
        SetLastError(dbResult.msg);
        CleanupContext();
        return false;
    }
    
    // 2. 如果提供了特征码，则也 Hook MD5 图片密钥 (手动扫描)
    bool enableMd5Hook = (md5Pattern != nullptr && strlen(md5Pattern) > 0);
    uintptr_t md5HookAddress = 0;
    if (enableMd5Hook) {
        RemoteModuleInfo moduleInfo;
        if (!scanner.GetRemoteModuleInfo(ObfuscatedStrings::GetWeixinDllName(), moduleInfo)) {
            SetLastError("未找到Weixin.dll模块");
            CleanupContext();
            return false;
        }
        std::vector<BYTE> md5PatternBytes = HexStringToBytes(md5Pattern);
        std::vector<uintptr_t> md5Results = scanner.FindAllPatterns(moduleInfo, md5PatternBytes.data(), md5Mask);
        if (md5Results.size() != 1) {
            SetLastError("MD5 特征码匹配失败");
            CleanupContext();
            return false;
        }
        md5HookAddress = md5Results[0] + md5Offset;
    }

    SendStatus("Hook 地址定位成功", 0);

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

    // 安装 DB Key Hook (始终安装)
    g_ctx.keyHooker = std::make_unique<RemoteHooker>(g_ctx.hProcess);
    ShellcodeConfig keyConfig{};
    keyConfig.sharedMemoryAddress = g_ctx.remoteData.get();
    keyConfig.enableStackSpoofing = true;
    keyConfig.spoofStackPointer = spoofStackTop;
    keyConfig.type = HookType::DB_KEY;
    if (!g_ctx.keyHooker->InstallHook(dbResult.target, keyConfig)) {
        SetLastError("安装 DB Key Hook 失败");
        CleanupContext(); 
        return false;
    }

    // 安装 MD5 Hook (按需安装)
    if (enableMd5Hook) {
        g_ctx.md5Hooker = std::make_unique<RemoteHooker>(g_ctx.hProcess);
        ShellcodeConfig md5Config = keyConfig;
        md5Config.type = HookType::MD5;
        md5Config.spoofStackPointer = spoofStackTop - 0x1000;
        if (!g_ctx.md5Hooker->InstallHook(md5HookAddress, md5Config)) {
            SetLastError("安装 MD5 Hook 失败");
            CleanupContext(); 
            return false;
        }
    }

    g_ctx.initialized = true;
    if (enableMd5Hook) {
        SendStatus("双路 Hook 安装成功", 1);
    } else {
        SendStatus("数据库 Hook 安装成功 (未启用图片密钥 Hook)", 1);
    }
    return true;
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
        size_t len = (std::min)(g_ctx.pendingKeyData.length(), (size_t)keyBufferSize - 1);
        memcpy(keyBuffer, g_ctx.pendingKeyData.c_str(), len);
        keyBuffer[len] = '\0';
        g_ctx.hasNewKey = false;
        hasAnyData = true;
    }

    if (g_ctx.hasNewMd5 && md5Buffer && md5BufferSize >= 33) {
        size_t len = (std::min)(g_ctx.pendingMd5Data.length(), (size_t)md5BufferSize - 1);
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

// ========== 图片密钥获取（本地文件扫描，无需注入） ==========

namespace {
    std::wstring GetUserHomePath() {
        wchar_t* profilePath = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Profile, 0, NULL, &profilePath))) {
            std::wstring result(profilePath);
            CoTaskMemFree(profilePath);
            return result;
        }
        wchar_t buf[MAX_PATH];
        if (GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH)) return std::wstring(buf);
        return L"";
    }
    bool DirectoryExists(const std::wstring& path) {
        DWORD attr = GetFileAttributesW(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
    }
    std::vector<std::wstring> ListDirectory(const std::wstring& dir, bool dirsOnly = false) {
        std::vector<std::wstring> results;
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) return results;
        do {
            std::wstring name(fd.cFileName);
            if (name == L"." || name == L"..") continue;
            if (dirsOnly && !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!dirsOnly && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            results.push_back(name);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
        return results;
    }
    std::string WToUtf8(const std::wstring& wide) {
        if (wide.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
        if (size <= 0) return "";
        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), &result[0], size, nullptr, nullptr);
        return result;
    }
    std::string CleanWxid(const std::wstring& dirName) {
        std::string raw = WToUtf8(dirName);
        size_t first = raw.find('_');
        if (first == std::string::npos) return raw;
        size_t second = raw.find('_', first + 1);
        if (second == std::string::npos) return raw;
        return raw.substr(0, second);
    }
    std::string CalcMD5(const std::string& input) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string result;
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return "";
        if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return ""; }
        if (!CryptHashData(hHash, (const BYTE*)input.c_str(), (DWORD)input.size(), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return ""; }
        BYTE hash[16];
        DWORD hashLen = 16;
        if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (int i = 0; i < 16; i++) oss << std::setw(2) << (int)hash[i];
            result = oss.str();
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return result;
    }
}

HOOK_API bool GetImageKey(char* resultBuffer, int bufferSize) {
    if (!resultBuffer || bufferSize < 256) return false;
    std::wstring userHome = GetUserHomePath();
    if (userHome.empty()) return false;
    std::vector<std::wstring> fileDirCandidates = {
        userHome + L"\\Documents\\xwechat_files", userHome + L"\\xwechat_files",
        userHome + L"\\Documents\\WeChat Files", userHome + L"\\WeChat Files"
    };
    std::vector<std::string> accounts;
    for (const auto& fileDir : fileDirCandidates) {
        if (!DirectoryExists(fileDir)) continue;
        auto dirs = ListDirectory(fileDir, true);
        for (const auto& d : dirs) {
            std::string name = WToUtf8(d);
            if (name.substr(0, 5) != "wxid_") continue;
            std::string cleanId = CleanWxid(d);
            bool dup = false;
            for (const auto& a : accounts) if (a == cleanId) { dup = true; break; }
            if (!dup) accounts.push_back(cleanId);
        }
    }
    if (accounts.empty()) accounts.push_back("unknown");
    std::wstring cacheDir = userHome + L"\\AppData\\Roaming\\Tencent\\xwechat\\net\\kvcomm";
    if (!DirectoryExists(cacheDir)) return false;
    std::vector<unsigned long long> uniqueCodes;
    std::regex pattern("key_(\\d+)_.+\\.statistic");
    auto files = ListDirectory(cacheDir, false);
    for (const auto& f : files) {
        std::string fname = WToUtf8(f);
        std::smatch match;
        if (std::regex_match(fname, match, pattern)) {
            unsigned long long code = std::stoull(match[1].str());
            if (code > 0 && code <= 4294967295ULL) {
                bool dup = false;
                for (auto c : uniqueCodes) if (c == code) { dup = true; break; }
                if (!dup) uniqueCodes.push_back(code);
            }
        }
    }
    if (uniqueCodes.empty()) return false;
    std::ostringstream json;
    json << "{\"accounts\":[";
    for (size_t ai = 0; ai < accounts.size(); ai++) {
        if (ai > 0) json << ",";
        json << "{\"wxid\":\"" << accounts[ai] << "\",\"keys\":[";
        for (size_t ki = 0; ki < uniqueCodes.size(); ki++) {
            if (ki > 0) json << ",";
            unsigned long long code = uniqueCodes[ki];
            int xorKey = (int)(code & 0xff);
            std::string dataToHash = std::to_string(code) + accounts[ai];
            std::string md5Full = CalcMD5(dataToHash);
            std::string aesKey = md5Full.substr(0, 16);
            json << "{\"code\":" << code << ",\"xorKey\":" << xorKey << ",\"aesKey\":\"" << aesKey << "\"}";
        }
        json << "]}";
    }
    json << "]}";
    std::string result = json.str();
    if ((int)result.size() >= bufferSize) return false;
    memcpy(resultBuffer, result.c_str(), result.size());
    resultBuffer[result.size()] = '\0';
    return true;
}
