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

#endif // HOOK_CONTROLLER_H
