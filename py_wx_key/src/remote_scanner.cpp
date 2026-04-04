#include "../include/remote_scanner.h"
#include "../include/syscalls.h"
#include "../include/string_obfuscator.h"
#include <Psapi.h>
#include <array>
#include <exception>
#include <sstream>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "version.lib")

const char* kSupportedRange = "4.0.x 及以上 4.x 版本";

// 版本配置管理器静态成员
std::vector<WeChatVersionConfig> VersionConfigManager::configs;
bool VersionConfigManager::initialized = false;

namespace {
    using VersionArray = std::array<int, 4>;

    bool ParseVersionString(const std::string& version, VersionArray& outParts) {
        outParts.fill(0);
        std::stringstream ss(version);
        std::string segment;
        size_t index = 0;

        while (std::getline(ss, segment, '.') && index < outParts.size()) {
            try {
                outParts[index++] = std::stoi(segment);
            } catch (const std::exception&) {
                return false;
            }
        }

        return index > 0;
    }

    int CompareVersions(const VersionArray& lhs, const VersionArray& rhs) {
        for (size_t i = 0; i < lhs.size(); ++i) {
            if (lhs[i] < rhs[i]) return -1;
            if (lhs[i] > rhs[i]) return 1;
        }
        return 0;
    }
}

void VersionConfigManager::InitializeConfigs() {
    if (initialized) return;

    // 微信 4.1.6.14 以上配置
    configs.push_back(WeChatVersionConfig(
        ">4.1.6.14",
        { 0x24, 0x50, 0x48, 0xC7, 0x45, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0x44, 0x89, 0xCF, 0x44, 0x89, 0xC3, 0x49, 0x89, 0xD6, 0x48, 0x89, 0xCE, 0x48, 0x89 },
        "xxxxxxxxxxxxxxxxxxxxxxxx",
        -3
    ));


    // 微信 4.1.4 至 4.1.6.14 配置（含 4.1.4.x、4.1.5.x、4.1.6.14）
    configs.push_back(WeChatVersionConfig(
        ">=4.1.4 && <=4.1.6.14",
        { 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x00, 0x18, 0x48, 0x89, 0x7c, 0x00, 0x20, 0x41, 0x56, 0x48, 0x83, 0xec, 0x50, 0x41 },
        "xxxxxxxxxx?xxxx?xxxxxxxx",
        -3
    ));

    // 微信 4.1.4 以下（含 4.1.0-4.1.3 与 4.0.x）的通用配置
    configs.push_back(WeChatVersionConfig(
        "<4.1.4",
        { 0x24, 0x50, 0x48, 0xc7, 0x45, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x44, 0x89, 0xcf, 0x44, 0x89, 0xc3, 0x49, 0x89, 0xd6, 0x48, 0x89, 0xce, 0x48, 0x89 },
        "xxxxxxxxxxxxxxxxxxxxxxxx",
        -0xf
    ));

    initialized = true;
}

const WeChatVersionConfig* VersionConfigManager::GetConfigForVersion(const std::string& version) {
    InitializeConfigs();

    if (configs.size() < 3 || version.empty()) {
        return nullptr;
    }

    VersionArray parsedVersion;
    if (!ParseVersionString(version, parsedVersion)) {
        return nullptr;
    }

    constexpr VersionArray baseline414 = { 4, 1, 4, 0 };
    constexpr VersionArray baseline41614 = { 4, 1, 6, 14 };

    if (CompareVersions(parsedVersion, baseline41614) > 0) {
        return &configs[0];
    }

    if (CompareVersions(parsedVersion, baseline414) >= 0 &&
        CompareVersions(parsedVersion, baseline41614) <= 0) {
        return &configs[1];
    }

    if ((parsedVersion[0] == 4 && parsedVersion[1] == 1 && parsedVersion[2] < 4) ||
        (parsedVersion[0] == 4 && parsedVersion[1] == 0)) {
        return &configs[2];
    }

    return nullptr;
}

// RemoteScanner实现
RemoteScanner::RemoteScanner(HANDLE hProcess)
    : hProcess(hProcess)
{
    scanBuffer.reserve(2 * 1024 * 1024);
}

RemoteScanner::~RemoteScanner() {
}

bool RemoteScanner::GetRemoteModuleInfo(const std::string& moduleName, RemoteModuleInfo& outInfo) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(this->hProcess, hMods, sizeof(hMods), &cbNeeded)) return false;
    DWORD moduleCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < moduleCount; i++) {
        char szModName[MAX_PATH];
        if (GetModuleBaseNameA(this->hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
            if (_stricmp(szModName, moduleName.c_str()) == 0) {
                MODULEINFO modInfo;
                if (GetModuleInformation(this->hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    outInfo.baseAddress = hMods[i];
                    outInfo.imageSize = modInfo.SizeOfImage;
                    outInfo.moduleName = szModName;
                    return true;
                }
            }
        }
    }
    return false;
}

bool RemoteScanner::SearchForHookAddress(ScanResult& result) {
    if (hProcess == NULL) {
        result.msg = "进程句柄为空";
        return false;
    }

    // 获取微信版本
    std::string wechatVersion = GetWeChatVersion();
    if (wechatVersion.empty()) {
        result.msg = "获取微信版本失败，目标进程可能已退出";
        return false;
    }

    //获取版本配置
    const WeChatVersionConfig* config = VersionConfigManager::GetConfigForVersion(wechatVersion);
    if (!config) {
        std::string errorMsg = std::string(u8"不支持的微信版本: ") + wechatVersion + "，支持范围: " + kSupportedRange;
        result.msg = errorMsg;
        return false;
    }

    // 扫描函数
    std::string weixinDll = ObfuscatedStrings::GetWeixinDllName();
    RemoteModuleInfo moduleInfo;

    if (!GetRemoteModuleInfo(weixinDll, moduleInfo)) {
        result.msg = "未找到Weixin.dll模块";
        return false;
    }

    std::vector<uintptr_t> results = FindAllPatterns(
        moduleInfo,
        config->pattern.data(),
        config->mask.c_str()
    );

    if (results.size() != 1) {
        std::stringstream errorMsg;
        errorMsg << u8"模式匹配失败，找到 " << results.size() << u8" 个结果";
        result.msg = errorMsg.str();
        return false;
    }

    result.target = results[0] + config->offset;
    return true;
}

bool RemoteScanner::MatchPattern(const BYTE* data, const BYTE* pattern, const char* mask, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (mask[i] != '?' && data[i] != pattern[i]) return false;
    }
    return true;
}

std::vector<uintptr_t> RemoteScanner::FindAllPatterns(const RemoteModuleInfo& moduleInfo, const BYTE* pattern, const char* mask) {
    std::vector<uintptr_t> results;
    size_t patternLength = strlen(mask);
    uintptr_t baseAddress = (uintptr_t)moduleInfo.baseAddress;
    SIZE_T imageSize = moduleInfo.imageSize;
    const SIZE_T CHUNK_SIZE = 1024 * 1024;
    scanBuffer.resize(CHUNK_SIZE + patternLength);
    for (SIZE_T offset = 0; offset < imageSize; offset += CHUNK_SIZE) {
        SIZE_T readSize = min(CHUNK_SIZE + patternLength, imageSize - offset);
        SIZE_T bytesRead = 0;
        NTSTATUS status = IndirectSyscalls::NtReadVirtualMemory(this->hProcess, (PVOID)(baseAddress + offset), scanBuffer.data(), readSize, &bytesRead);
        if (status != STATUS_SUCCESS || bytesRead < patternLength) continue;
        for (SIZE_T i = 0; i + patternLength <= bytesRead; ++i) {
            if (MatchPattern(&scanBuffer[i], pattern, mask, patternLength)) results.push_back(baseAddress + offset + i);
        }
    }
    return results;
}

std::string RemoteScanner::GetWeChatVersion() {
    std::string weixinDllName = ObfuscatedStrings::GetWeixinDllName();
    RemoteModuleInfo moduleInfo;
    if (!GetRemoteModuleInfo(weixinDllName, moduleInfo)) return "";
    WCHAR modulePath[MAX_PATH];
    if (GetModuleFileNameExW(this->hProcess, moduleInfo.baseAddress, modulePath, MAX_PATH) == 0) return "";
    DWORD handle = 0;
    DWORD versionSize = GetFileVersionInfoSizeW(modulePath, &handle);
    if (versionSize == 0) return "";
    std::vector<BYTE> versionData(versionSize);
    if (!GetFileVersionInfoW(modulePath, handle, versionSize, versionData.data())) return "";
    VS_FIXEDFILEINFO* fileInfo = nullptr;
    UINT fileInfoSize = 0;
    if (VerQueryValueW(versionData.data(), L"\\", (LPVOID*)&fileInfo, &fileInfoSize) && fileInfo) {
        std::stringstream ss;
        ss << HIWORD(fileInfo->dwProductVersionMS) << "." << LOWORD(fileInfo->dwProductVersionMS) << "." << HIWORD(fileInfo->dwProductVersionLS) << "." << LOWORD(fileInfo->dwProductVersionLS);
        return ss.str();
    }
    return "";
}
