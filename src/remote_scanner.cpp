#include "../include/remote_scanner.h"
#include "../include/syscalls.h"
#include "../include/string_obfuscator.h"
#include <Psapi.h>
#include <array>
#include <exception>
#include <sstream>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "version.lib")

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

bool RemoteScanner::MatchPattern(const BYTE* data, const BYTE* pattern, const char* mask, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (mask[i] != '?' && data[i] != pattern[i]) return false;
    }
    return true;
}

uintptr_t RemoteScanner::FindPattern(const RemoteModuleInfo& moduleInfo, const BYTE* pattern, const char* mask) {
    auto results = FindAllPatterns(moduleInfo, pattern, mask);
    return results.empty() ? 0 : results[0];
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

bool RemoteScanner::ReadRemoteMemory(uintptr_t address, void* buffer, SIZE_T size) {
    SIZE_T bytesRead = 0;
    NTSTATUS status = IndirectSyscalls::NtReadVirtualMemory(this->hProcess, (PVOID)address, buffer, size, &bytesRead);
    return (status == STATUS_SUCCESS && bytesRead == size);
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
