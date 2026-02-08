#ifndef REMOTE_SCANNER_H
#define REMOTE_SCANNER_H

#include <Windows.h>
#include <vector>
#include <string>

// 远程进程信息
struct RemoteModuleInfo {
    HMODULE baseAddress;
    SIZE_T imageSize;
    std::string moduleName;
};

// 远程特征码扫描器
class RemoteScanner {
public:
    RemoteScanner(HANDLE hProcess);
    ~RemoteScanner();
    
    // 获取远程进程的模块信息
    bool GetRemoteModuleInfo(const std::string& moduleName, RemoteModuleInfo& outInfo);
    
    // 在远程进程中查找特征码（单个结果）
    uintptr_t FindPattern(const RemoteModuleInfo& moduleInfo, const BYTE* pattern, const char* mask);
    
    // 在远程进程中查找特征码（所有结果）
    std::vector<uintptr_t> FindAllPatterns(const RemoteModuleInfo& moduleInfo, const BYTE* pattern, const char* mask);
    
    // 读取远程内存
    bool ReadRemoteMemory(uintptr_t address, void* buffer, SIZE_T size);
    
    // 获取微信版本号
    std::string GetWeChatVersion();
    
private:
    HANDLE hProcess;
    
    // 本地缓冲区，用于批量读取远程内存
    std::vector<BYTE> scanBuffer;
    
    // 内存匹配辅助函数
    bool MatchPattern(const BYTE* data, const BYTE* pattern, const char* mask, size_t length);
};

#endif // REMOTE_SCANNER_H
