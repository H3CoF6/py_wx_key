#pragma once

#include <sys/types.h>

#include <atomic>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

struct user_regs_struct;

// Linux 数据库密钥捕获器（PTRACE_TRACEME 自启动版）。
//
// 与 Xkey 的 linux_hooker（attach 已运行进程 + root）不同，本实现由 wx_key
// 扩展自行 fork + exec 拉起微信：父进程天然是 tracer，**零提权**，Yama
// ptrace_scope 无关。不注入、不改写进程代码：只用 DR0/DR7 硬件执行断点 +
// 寄存器/内存快照，命中登录 PBKDF 配置写入函数时读取参数：
//   rsi + 0x08 -> const uint8_t* key（要求 32 字节）
//   rsi + 0x10 -> uint32_t keyLen
//
// ⚠️ 历史踩坑（勿删，勿"修复"）：
//   微信 AppImage 版本通过 FUSE 挂载运行，而 FUSE 挂载对 root 不可见——
//   以 root 身份启动 AppImage 会直接失败（"找不到可执行文件"）。
//   因此本模块**永远不要**用 root / pkexec / sudo 启动微信或运行扩展；
//   TRACEME 自启动本身就是零提权方案：微信始终以登录用户身份运行，
//   AppImage/FUSE 一切正常。
class LinuxHooker {
public:
    LinuxHooker();
    ~LinuxHooker();

    // fork + PTRACE_TRACEME + exec(path, args)，等待 exec-stop 后返回。
    // 子进程停在 execve 装入新镜像后、执行任何指令之前（父进程可读 /proc，
    // dumpable 尚未被目标代码修改）。
    bool Spawn(const std::string& path, const std::vector<std::string>& args,
               std::string& outErr);

    pid_t childPid() const { return childPid_; }

    // 从 /proc/<pid>/maps 解析主可执行映像加载基址（PIE load bias）。
    uintptr_t ResolveLoadBias(std::string& outErr);

    // 给当前所有已跟踪线程装 DR0 硬件执行断点并继续运行。
    bool ArmBreakpoint(uintptr_t runtimeAddr, std::string& outErr);

    // 阻塞式捕获循环：处理 clone/exit/信号/断点命中，直到成功、超时或
    // RequestStop。成功后 outKeyHex 为 64 位小写 hex，并已 detach——
    // 微信继续正常运行（登录流程不中断）。
    bool RunCapture(int timeoutMs, std::string& outKeyHex, std::string& outErr);

    // 让 RunCapture 尽快退出并 detach（可被其他线程调用）。
    void RequestStop();

    // 停住全部线程 -> 清断点 -> detach -> SIGCONT（恢复登录流程）。
    bool DetachAll();

private:
    pid_t childPid_ = -1;
    uintptr_t bpAddr_ = 0;
    std::atomic<bool> stop_{false};
    std::atomic<bool> armed_{false};
    std::set<pid_t> tids_;
    std::set<pid_t> armedTids_;  // 已装过断点的线程（新线程在其首次 stop 时补装）
    pid_t hitTid_ = -1;
    int cloneLogCount_ = 0;  // 仅前几次 clone 打印 DR 健康度，避免刷屏

    bool ReadMemory(uintptr_t addr, void* buffer, size_t size);
    static std::string HexEncode(const uint8_t* data, size_t len);
    bool SetHwBp(pid_t tid);   // 用 bpAddr_/bpAddr2_ 装断点（DR0/DR1）
    static bool ClearHwBp(pid_t tid);

    // 命中目标地址后读取 key 参数；成功返回 true（调用方负责收尾）。
    bool TryReadKey(pid_t tid, const struct user_regs_struct& regs, std::string& outKeyHex);
};