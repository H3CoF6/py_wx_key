#ifndef HOOK_CONTROLLER_H
#define HOOK_CONTROLLER_H

#include <Windows.h>

#ifdef HOOK_EXPORTS
#define HOOK_API extern "C" __declspec(dllexport)
#else
#define HOOK_API extern "C" __declspec(dllimport)
#endif

/**
 * 初始化并安装Hook
 * @param targetPid 微信进程的PID
 * @param version 微信版本号字符串 (如 "4.1.6.14")，如果不需要版本校验可传空
 * @param pattern 特征码十六进制字符串 (如 "24 50 48 C7 45 00 FE FF FF FF")
 * @param mask 掩码字符串 (如 "xxxxxxxxxx")，'x'表示匹配，'?'表示忽略
 * @param offset 匹配成功后的偏移量
 * @return 成功返回true，失败返回false
 */
HOOK_API bool InitializeHook(DWORD targetPid, const char* version, const char* pattern, const char* mask, int offset);

/**
 * 轮询检查是否有新的密钥数据（非阻塞）
 * @param keyBuffer 输出缓冲区，用于接收密钥十六进制字符串（至少65字节）
 * @param bufferSize keyBuffer的大小
 * @return 如果有新数据返回true，否则返回false
 */
HOOK_API bool PollKeyData(char* keyBuffer, int bufferSize);

/**
 * 获取当前状态消息
 * @param statusBuffer 输出缓冲区，用于接收状态消息（至少256字节）
 * @param bufferSize statusBuffer的大小
 * @param outLevel 输出状态级别 (0=info, 1=success, 2=error)
 * @return 如果有新状态返回true，否则返回false
 */
HOOK_API bool GetStatusMessage(char* statusBuffer, int bufferSize, int* outLevel);

/**
 * 清理并卸载Hook
 * @return 成功返回true，失败返回false
 */
HOOK_API bool CleanupHook();

/**
 * 获取最后一次错误信息
 * @return 错误信息字符串
 */
HOOK_API const char* GetLastErrorMsg();

#endif // HOOK_CONTROLLER_H
