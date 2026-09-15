#ifndef HOOK_CONTROLLER_H
#define HOOK_CONTROLLER_H

#ifdef _WIN32
#include <Windows.h>

#ifdef HOOK_EXPORTS
#define HOOK_API extern "C" __declspec(dllexport)
#else
#define HOOK_API extern "C" __declspec(dllimport)
#endif

/**
 * 初始化并安装Hook
 * @param targetPid 微信进程的PID
 * @param md5Pattern 可选：图片密钥特征码。如果不传或为空，则只Hook数据库密钥。
 * @param md5Mask 可选：图片密钥掩码
 * @param md5Offset 可选：图片密钥偏移
 * @return 成功返回true，失败返回false
 */
HOOK_API bool InitializeHook(
    DWORD targetPid,
    const char* md5Pattern = nullptr,
    const char* md5Mask = nullptr,
    int md5Offset = 0
);

/**
 * 获取图片密钥（通过本地文件算法计算，推荐方式）
 */
HOOK_API bool GetImageKey(char* resultBuffer, int bufferSize);

/**
 * 轮询检查是否有新的密钥数据（非阻塞）
 */
HOOK_API bool PollKeyData(char* keyBuffer, int keyBufferSize, char* md5Buffer, int md5BufferSize);

/**
 * 获取当前状态消息
 */
HOOK_API bool GetStatusMessage(char* statusBuffer, int bufferSize, int* outLevel);

/**
 * 清理并卸载Hook
 */
HOOK_API bool CleanupHook();

/**
 * 获取最后一次错误信息
 */
HOOK_API const char* GetLastErrorMsg();

#else  // _WIN32

#define HOOK_API extern "C"

/* ==================== Linux（linux_hook_controller.cpp） ====================
 *
 * 与 Windows 相同的 API 语义，差异仅在第一个参数：
 *   - Windows 接的是"已运行微信的 pid"（WCDA 先杀微信再拉起）；
 *   - Linux 接的是微信可执行文件路径 —— 扩展自行 fork+exec（PTRACE_TRACEME）
 *     拉起微信，零提权，父进程天然是 tracer。
 *
 * ⚠️ AppImage 微信的 FUSE 坑：FUSE 挂载对 root 不可见，勿以 root/pkexec/sudo
 *    启动微信或本扩展 —— TRACEME 自启动本身就是零提权方案。
 */

/**
 * 启动微信（TRACEME 自启动）并布防数据库密钥 Hook。
 * 成功后微信窗口已出现，等待用户扫码登录；登录 PBKDF 触发断点时自动取参。
 * 返回 false 时用 LinuxGetLastErrorMsg() 取原因。
 */
HOOK_API bool LinuxInitializeHook(const char* wechatPath);

/**
 * 轮询捕获到的密钥数据（非阻塞）。成功返回 64 位小写 hex。
 */
HOOK_API bool LinuxPollKeyData(char* keyBuffer, int keyBufferSize);

/**
 * 获取当前状态消息（与 Windows 相同的二元组语义）
 */
HOOK_API bool LinuxGetStatusMessage(char* statusBuffer, int bufferSize, int* outLevel);

/**
 * 清理：detach 微信（继续正常运行）、停止捕获线程。
 */
HOOK_API bool LinuxCleanupHook();

/**
 * 获取最后一次错误信息
 */
HOOK_API const char* LinuxGetLastErrorMsg();

#endif  // _WIN32

#endif  // HOOK_CONTROLLER_H