// Linux 数据库密钥控制器：跑 wx_key 的 C ABI（与 Windows hook_controller.cpp
// 同一语义），底层是 TRACEME 自启动 + DR0 硬件断点。
//
// 流程（**全部在同一个 worker 线程内完成**，见下方线程亲和性说明）：
//   LinuxInitializeHook(path)
//     1) 起 worker 线程，由该线程 fork + PTRACE_TRACEME + exec(微信) —— 零提权
//     2) exec-stop 上解析加载基址（子进程尚未执行任何代码，/proc 必可读）
//     3) LinuxScanner 读 /proc/<pid>/exe 推导 sink 的 ELF VA（锚点，零特权）
//     4) ArmBreakpoint(runtime = bias + VA)，放行微信
//     5) 同一线程进入捕获循环：登录 PBKDF 命中断点时读 rsi+0x08/0x10 取 32 字节 key
//     initialize_hook 通过条件变量等待"已布防 / 已失败"，保持同步 ABI。
//   LinuxPollKeyData / LinuxGetStatusMessage：与 Windows 形状一致
//   LinuxCleanupHook：RequestStop + join（worker 自行 detach，微信继续运行）
//
// ⚠️ 线程亲和性（本文件最关键的一条约束，勿"重构"掉）：
//   ptrace 的跟踪关系绑定在**发起 fork 的那个线程**上。fork 建立的 tracee 其
//   `task->parent` 是 fork 调用线程；此后对该 tracee 的任何 ptrace 请求
//   （GETREGS/GETSIGINFO/CONT/POKEUSER/DETACH…）都必须由同一线程发起。
//   若在别的线程调用，waitpid 仍能收到 stop 事件（waitpid 是进程级的），
//   但所有 ptrace 请求会返回 ESRCH(errno 3)，表现为"微信停住不动、窗口不出现"。
//   已实测：单线程 fork+ptrace 正常；跨线程则 GETREGS/CONT 全 ESRCH。
//   因此 Spawn/Arm/RunCapture/DetachAll 必须串在同一个 worker 线程里，
//   initialize_hook 只用条件变量与它同步，绝不能自己 fork。
//
// 信任边界：不信任任何外部 pid —— 微信是本扩展自己的子进程；也不需要
// fd+nonce / SO_PEERCRED 那套（Windows 侧本来也只是 pid 直传 OpenProcess）。
#include "hook_controller.h"
#include "linux_hooker.h"
#include "linux_scanner.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

struct StatusMessage {
    std::string message;
    int level = 0;
};

std::mutex g_mu;
std::condition_variable g_cv;
std::deque<StatusMessage> g_statusQueue;
std::string g_pendingKey;  // 64 位小写 hex
std::string g_lastError;
bool g_initialized = false;

// worker 初始化阶段的结果（由 worker 写入、initialize_hook 读取）
bool g_armReady = false;
bool g_armOk = false;
std::string g_armErr;

LinuxHooker g_hooker;
std::thread g_worker;
std::atomic<bool> g_workerRunning{false};

constexpr int kCaptureTimeoutMs = 300000;   // 5 分钟（WCDA 轮询窗口由其自行决定）
constexpr int kArmReadyTimeoutMs = 120000;  // 等"已布防/已失败"的上限（含锚点扫描）

void PushStatus(const std::string& msg, int level) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_statusQueue.push_back({msg, level});
    if (g_statusQueue.size() > 100) g_statusQueue.pop_front();
}

void PushError(const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_lastError = msg;
    g_statusQueue.push_back({msg, 2});
}

// worker 初始化阶段结束（成功布防或失败）后唤醒 initialize_hook
void SignalArmResult(bool ok, const std::string& err) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_armOk = ok;
    g_armErr = err;
    g_armReady = true;
    g_cv.notify_all();
}

// 整个 ptrace 会话（fork → 扫描 → 布防 → 捕获 → detach）都在本线程内完成。
void WorkerMain(const std::string& wechatPath) {
    std::string err;

    // 1. 拉起微信（TRACEME），停在 exec-stop。fork 发生在本线程 ⇒ 本线程即 tracer。
    const std::vector<std::string> args = {wechatPath};
    if (!g_hooker.Spawn(wechatPath, args, err)) {
        PushError("启动微信失败: " + err);
        SignalArmResult(false, err);
        return;
    }
    PushStatus("微信进程已创建 (pid " + std::to_string(g_hooker.childPid()) + ")", 0);

    // 2. 解析加载基址（此时子进程尚未执行任何代码，/proc 必可读）
    const uintptr_t bias = g_hooker.ResolveLoadBias(err);
    if (bias == 0) {
        PushError("解析加载基址失败: " + err);
        g_hooker.DetachAll();
        SignalArmResult(false, err);
        return;
    }

    // 3. 锚点扫描：读运行中的真实镜像（/proc/<pid>/exe），零特权
    LinuxScanner scanner;
    ScanResult scan;
    char exeLink[64] = {0};
    std::snprintf(exeLink, sizeof(exeLink), "/proc/%d/exe", static_cast<int>(g_hooker.childPid()));
    if (!scanner.SearchForHookAddress(exeLink, scan) || scan.targetVA == 0) {
        const std::string msg = "锚点定位失败: " + (scan.msg.empty() ? std::string("unknown") : scan.msg);
        PushError(msg);
        g_hooker.DetachAll();
        SignalArmResult(false, msg);
        return;
    }

    // 4. 布防断点并放行微信
    const uintptr_t targetAddr = bias + scan.targetVA;
    if (!g_hooker.ArmBreakpoint(targetAddr, err)) {
        PushError("布置硬件断点失败: " + err);
        g_hooker.DetachAll();
        SignalArmResult(false, err);
        return;
    }

    // 通知 initialize_hook：布防完成，微信已放行
    SignalArmResult(true, std::string());
    PushStatus("Hook 已布防，微信窗口应已出现，请扫码登录", 0);

    // 5. 同一线程内进入捕获循环（命中/超时/RequestStop 后自行 detach）
    std::string key;
    std::string capErr;
    const bool ok = g_hooker.RunCapture(kCaptureTimeoutMs, key, capErr);
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (ok) {
            g_pendingKey = key;
            g_statusQueue.push_back({"已成功接收到Hook数据", 1});
        }
    }
    if (!ok) PushStatus("捕获结束: " + capErr, 1);
    // RunCapture 内部已 DetachAll；这里再兜一次幂等清理
    g_hooker.DetachAll();
    g_workerRunning = false;
}

}  // namespace

// 注意：g_mu 是非递归互斥量。除明确标注的短临界区外，本函数全程**不持锁**——
// PushStatus/PushError 内部自己加锁，长操作（Spawn/扫描/布防）期间绝不能持锁，
// 否则第一次 PushStatus 就会自锁死（此坑已踩过：fork 之前就卡死，外部表现为
// "initialize_hook 永不返回且微信进程从未出现"）。
extern "C" bool LinuxInitializeHook(const char* wechatPath) {
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_initialized) {
            g_lastError = "Hook 已经初始化";
            return false;
        }
        if (!wechatPath || !*wechatPath) {
            g_lastError = "微信路径为空";
            return false;
        }
        g_statusQueue.clear();
        g_pendingKey.clear();
        g_lastError.clear();
        g_armReady = false;
        g_armOk = false;
        g_armErr.clear();
    }
    PushStatus("开始初始化 Linux Hook 系统...", 0);

    // 起 worker；fork 与后续所有 ptrace 都在该线程内（线程亲和性要求）。
    const std::string path = wechatPath;
    g_workerRunning = true;
    g_worker = std::thread([path] { WorkerMain(path); });

    bool ready = false;
    {
        std::unique_lock<std::mutex> lk(g_mu);
        ready = g_cv.wait_for(lk, std::chrono::milliseconds(kArmReadyTimeoutMs),
                              [] { return g_armReady; });
    }

    if (!ready) {
        // worker 卡在初始化（极少见）：请求停止并收拢线程
        g_hooker.RequestStop();
        if (g_worker.joinable()) g_worker.join();
        PushError("Linux Hook 初始化超时");
        return false;
    }

    if (!g_armOk) {
        if (g_worker.joinable()) g_worker.join();
        // 失败细节已由 worker 经 PushError 入队；g_lastError 同步一份
        std::lock_guard<std::mutex> lk(g_mu);
        g_lastError = g_armErr;
        return false;
    }

    std::lock_guard<std::mutex> lk(g_mu);
    g_initialized = true;
    return true;
}

extern "C" bool LinuxPollKeyData(char* keyBuffer, int keyBufferSize) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_initialized || !keyBuffer || keyBufferSize <= 0) return false;
    keyBuffer[0] = '\0';
    if (g_pendingKey.empty()) return false;
    const size_t n = std::min(g_pendingKey.size(), static_cast<size_t>(keyBufferSize) - 1);
    std::memcpy(keyBuffer, g_pendingKey.c_str(), n);
    keyBuffer[n] = '\0';
    g_pendingKey.clear();
    return true;
}

extern "C" bool LinuxGetStatusMessage(char* statusBuffer, int bufferSize, int* outLevel) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (!statusBuffer || bufferSize < 256 || !outLevel) return false;
    if (g_statusQueue.empty()) return false;
    const StatusMessage msg = g_statusQueue.front();
    g_statusQueue.pop_front();
    const size_t n = std::min(msg.message.size(), static_cast<size_t>(bufferSize) - 1);
    std::memcpy(statusBuffer, msg.message.c_str(), n);
    statusBuffer[n] = '\0';
    *outLevel = msg.level;
    return true;
}

extern "C" bool LinuxCleanupHook() {
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (!g_initialized && !g_worker.joinable()) return true;
    }

    // 让捕获循环尽快退出；worker 自己 detach（微信继续运行）。
    g_hooker.RequestStop();
    if (g_worker.joinable()) g_worker.join();

    std::lock_guard<std::mutex> lk(g_mu);
    g_pendingKey.clear();
    g_statusQueue.clear();
    g_initialized = false;
    return true;
}

extern "C" const char* LinuxGetLastErrorMsg() {
    static thread_local std::string s;
    std::lock_guard<std::mutex> lk(g_mu);
    s = g_lastError;
    return s.c_str();
}
