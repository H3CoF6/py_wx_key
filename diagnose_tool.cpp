#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

// 定义函数原型（与 dll 导出一致）
typedef bool (*pInitializeHook)(DWORD, const char*, const char*, int);
typedef const char* (*pGetLastErrorMsg)();

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

DWORD GetWeChatPid(std::wstring& outName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snapshot, &pe)) {
            do {
                std::wstring name = pe.szExeFile;
                if (name == L"WeChat.exe" || name == L"weixin.exe") {
                    pid = pe.th32ProcessID;
                    outName = name;
                    break;
                }
            } while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

int main() {
    system("chcp 65001 > nul"); // 设置 UTF-8 输出
    std::cout << "============================================================" << std::endl;
    std::cout << "          WeChat DB Hook 独立环境诊断工具 (C++版)           " << std::endl;
    std::cout << "============================================================" << std::endl;

    // 1. 权限检查
    std::cout << "[*] 管理员权限: " << (IsAdmin() ? "[OK] 是" : "[!!] 否 (建议右键管理员运行)") << std::endl;

    // 2. 进程检查
    std::wstring procName;
    DWORD pid = GetWeChatPid(procName);
    if (pid == 0) {
        std::cout << "[!] 未找到运行中的 WeChat.exe 或 weixin.exe" << std::endl;
    } else {
        std::wcout << L"[OK] 找到目标进程: " << procName << L" (PID: " << pid << L")" << std::endl;
    }

    // 3. 寻找 DLL/PYD
    const wchar_t* dllCandidates[] = { L"wx_key.pyd", L"wx_key.dll", L"py_wx_key/build/Release/wx_key.pyd" };
    HMODULE hDll = NULL;
    std::wstring foundPath;

    for (auto path : dllCandidates) {
        hDll = LoadLibraryW(path);
        if (hDll) {
            foundPath = path;
            break;
        }
    }

    if (!hDll) {
        std::cout << "[!] 错误: 找不到 wx_key.pyd 或 wx_key.dll，请确保它在当前目录。" << std::endl;
    } else {
        std::wcout << L"[OK] 成功加载模块: " << foundPath << std::endl;

        // 4. 获取导出函数
        pInitializeHook initHook = (pInitializeHook)GetProcAddress(hDll, "InitializeHook");
        pGetLastErrorMsg getError = (pGetLastErrorMsg)GetProcAddress(hDll, "GetLastErrorMsg");

        if (!initHook || !getError) {
            std::cout << "[!] 错误: DLL 中未找到 InitializeHook 或 GetLastErrorMsg 导出函数。" << std::endl;
            std::cout << "    请确认编译时使用了 __declspec(dllexport) 或 .def 文件。" << std::endl;
        } else {
            if (pid != 0) {
                std::cout << "[*] 正在尝试调用 InitializeHook(" << pid << ")..." << std::endl;
                bool success = initHook(pid, nullptr, nullptr, 0);
                if (success) {
                    std::cout << "[OK] Hook 初始化成功！环境完全正常。" << std::endl;
                } else {
                    const char* msg = getError();
                    std::cout << "[X] 初始化失败！底层报错: " << (msg ? msg : "未知错误") << std::endl;
                    
                    std::string errStr = msg ? msg : "";
                    if (errStr.find("0xC000000B") != std::string::npos) {
                        std::cout << "\n[诊断结果] 错误码 0xC000000B (STATUS_INVALID_CID)" << std::endl;
                        std::cout << "1. 微信进程可能具有更高的权限 (UIPI) 或受到保护。" << std::endl;
                        std::cout << "2. 尝试关闭微信后，以普通用户身份重新打开微信。" << std::endl;
                        std::cout << "3. 检查是否有 360/火绒 等杀毒软件拦截了远程句柄打开。" << std::endl;
                    }
                }
            }
        }
        FreeLibrary(hDll);
    }

    std::cout << "============================================================" << std::endl;
    std::cout << "请将上述输出截图提供给开发人员。" << std::endl;
    std::cout << "按任意键退出..." << std::endl;
    getchar();
    return 0;
}
