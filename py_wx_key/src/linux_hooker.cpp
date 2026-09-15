#include "linux_hooker.h"

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <unistd.h>

#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

#if !defined(__x86_64__)
#error "linux_hooker 目前仅支持 x86_64"
#endif

namespace {

std::string ErrnoDesc(const std::string& ctx) {
    std::ostringstream oss;
    oss << ctx << " (errno " << errno << ": " << std::strerror(errno) << ")";
    return oss.str();
}

// 事件日志（WXK_DEBUG=<path> 时启用）：逐条记录 waitpid 事件，用于定位冻结。
struct DebugLog {
    FILE* f = nullptr;
    long t0 = 0;
    void Open() {
        const char* p = getenv("WXK_DEBUG");
        if (!p || !*p) return;
        f = fopen(p, "a");
        struct timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        t0 = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    }
    void Log(const char* fmt, ...) {
        if (!f) return;
        struct timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        const long now = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        std::fprintf(f, "[%6ldms] ", now - t0);
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(f, fmt, ap);
        va_end(ap);
        std::fputc('\n', f);
        std::fflush(f);
    }
};

DebugLog g_log;

}  // namespace

LinuxHooker::LinuxHooker() = default;

LinuxHooker::~LinuxHooker() {
    if (!tids_.empty()) DetachAll();
}

bool LinuxHooker::Spawn(const std::string& path, const std::vector<std::string>& args,
                        std::string& outErr) {
    if (childPid_ > 0) {
        outErr = "已存在受跟踪子进程";
        return false;
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);

    const pid_t pid = fork();
    if (pid < 0) {
        outErr = ErrnoDesc("fork 失败");
        return false;
    }

    if (pid == 0) {
        // 子进程：fork 后到 execv 之间只允许 async-signal-safe 调用。
        //
        // 注意：不设 PR_SET_PDEATHSIG —— 捕获完成 detach 后微信要继续独立运行，
        // 父进程（后端）退出不应顺带杀掉微信。
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(126);
        execv(path.c_str(), argv.data());
        static const char kMsg[] = "wx_key: execv failed\n";
        (void)write(STDERR_FILENO, kMsg, sizeof(kMsg) - 1);
        _exit(127);
    }

    g_log.Open();
    childPid_ = pid;

    // 等 exec-stop：TRACEME 下 execve 会以 SIGTRAP 停住子进程
    // （新镜像已装入、但一条指令都还没执行）。
    int status = 0;
    for (;;) {
        const pid_t r = waitpid(pid, &status, __WALL);
        if (r < 0) {
            if (errno == EINTR) continue;
            outErr = ErrnoDesc("waitpid(exec-stop) 失败");
            DetachAll();
            return false;
        }
        g_log.Log("Spawn wait: tid=%d status=0x%x", (int)r, status);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            const int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            outErr = "微信进程提前退出 (code " + std::to_string(code) + ")";
            childPid_ = -1;
            return false;
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) break;
        // 组停止等其他 stop：放行继续等
        ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    }

    tids_.insert(pid);

    // 选项必须在 tracee 停止时设置。
    // EXITKILL：捕获期间若后端进程意外退出，不留下"半跟踪"的微信僵尸；
    // detach 之后 EXITKILL 自动失效，微信恢复独立。
    const long opts = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, reinterpret_cast<void*>(opts)) < 0) {
        outErr = ErrnoDesc("PTRACE_SETOPTIONS 失败");
        DetachAll();
        return false;
    }
    g_log.Log("Spawn: exec-stop ok, opts set");
    return true;
}

uintptr_t LinuxHooker::ResolveLoadBias(std::string& outErr) {
    std::string exePath;
    {
        char buf[PATH_MAX] = {0};
        const std::string link = "/proc/" + std::to_string(childPid_) + "/exe";
        const ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
        if (n <= 0) {
            outErr = ErrnoDesc("readlink /proc/pid/exe 失败");
            return 0;
        }
        exePath.assign(buf, static_cast<size_t>(n));
    }
    g_log.Log("Resolve: /proc/%d/exe -> %s", (int)childPid_, exePath.c_str());

    std::ifstream maps("/proc/" + std::to_string(childPid_) + "/maps");
    std::string line;
    uintptr_t minAddr = ~uintptr_t(0);
    bool found = false;
    while (std::getline(maps, line)) {
        if (line.find(exePath) == std::string::npos) continue;
        const size_t dash = line.find('-');
        if (dash == std::string::npos) continue;
        const uintptr_t start = std::stoull(line.substr(0, dash), nullptr, 16);
        if (start < minAddr) {
            minAddr = start;
            found = true;
        }
    }
    if (!found) {
        outErr = "在 /proc/pid/maps 中未找到主映像映射";
        return 0;
    }
    return minAddr;
}

bool LinuxHooker::ArmBreakpoint(uintptr_t runtimeAddr, std::string& outErr) {
    if (tids_.empty()) {
        outErr = "没有已跟踪线程";
        return false;
    }
    bpAddr_ = runtimeAddr;
    for (const pid_t tid : tids_) {
        if (!SetHwBp(tid)) {
            outErr = ErrnoDesc("设置硬件断点失败 (tid " + std::to_string(tid) + ")");
            return false;
        }
        // 校验必须在 CONT 之前：tracee 处于运行态时 PEEKUSER 会失败（ESRCH），
        // 放在 CONT 之后只会打印出 0xffffffffffffffff 的假象。
        const unsigned long dr0 =
            ptrace(PTRACE_PEEKUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[0])), nullptr);
        const unsigned long dr7 =
            ptrace(PTRACE_PEEKUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[7])), nullptr);
        g_log.Log("Arm: DR0=0x%lx DR7=0x%lx (expect DR0=0x%lx DR7=0x1) tid=%d", dr0, dr7,
                  (unsigned long)runtimeAddr, (int)tid);
        // 自检：运行时该地址处的字节应正是锚点函数序言 55 41 57。
        // 若不符，说明 bias+VA 算错（或镜像与磁盘上那份不一致）。
        uint8_t pro[3] = {0, 0, 0};
        if (ReadMemory(runtimeAddr, pro, sizeof(pro))) {
            g_log.Log("Arm: bytes@0x%lx = %02x %02x %02x (expect 55 41 57)", (unsigned long)runtimeAddr,
                      pro[0], pro[1], pro[2]);
        } else {
            g_log.Log("Arm: 读 0x%lx 处字节失败（dumpable 被清？）", (unsigned long)runtimeAddr);
        }
        if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) < 0) {
            outErr = ErrnoDesc("PTRACE_CONT 失败 (tid " + std::to_string(tid) + ")");
            return false;
        }
        armedTids_.insert(tid);
    }
    armed_ = true;
    return true;
}

bool LinuxHooker::TryReadKey(pid_t tid, const struct user_regs_struct& regs, std::string& outKeyHex) {
    (void)tid;
    // 断点命中点：rsi 指向配置对象，rsi+0x08 为 key 指针，rsi+0x10 为长度
    uint32_t keyLen = 0;
    if (!ReadMemory(regs.rsi + 0x10, &keyLen, sizeof(keyLen))) {
        g_log.Log("  TryReadKey: 读 rsi+0x10 (keyLen) 失败");
        return false;
    }
    if (keyLen != 32) {  // 非目标调用（长度不符或布局已变）
        g_log.Log("  TryReadKey: keyLen=%u (期望 32)", keyLen);
        return false;
    }
    uintptr_t keyPtr = 0;
    if (!ReadMemory(regs.rsi + 0x08, &keyPtr, sizeof(keyPtr))) {
        g_log.Log("  TryReadKey: 读 rsi+0x08 (keyPtr) 失败");
        return false;
    }
    uint8_t key[32] = {0};
    if (!ReadMemory(keyPtr, key, sizeof(key))) {
        g_log.Log("  TryReadKey: 读 key @0x%llx 失败", (unsigned long long)keyPtr);
        return false;
    }
    outKeyHex = HexEncode(key, sizeof(key));
    return true;
}

bool LinuxHooker::RunCapture(int timeoutMs, std::string& outKeyHex, std::string& outErr) {
    if (!armed_) {
        outErr = "断点尚未布防";
        return false;
    }

    // 事件取用方式是本函数的命门：必须用阻塞的全局 waitpid(-1, __WALL)，
    // 逐 tid waitpid(tid, WNOHANG) 轮询会漏取事件 —— 实测微信主线程会停在
    // tracing stop 无人认领（state t / Threads:1），窗口永不出现；而阻塞式
    // 全局等待已被 ptrace_dbg/tests + 真实微信 GUI 验证可正常运行。
    // 超时靠"每次事件唤醒后检查"实现；微信运行中事件密集，最坏也只是
    // 超时精度受限于下一个事件的到来。
    const auto nowMs = [] {
        struct timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    };
    const long t0 = nowMs();
    bool captured = false;
    pid_t hitTid = -1;

    while (true) {
        // 停止/超时检测放在取事件之前：微信空闲（无新事件）时也要能及时退出，
        // 否则阻塞在 waitpid 上会把 cleanup 与超时一起挂住。
        if (stop_.load()) break;
        if (nowMs() - t0 >= timeoutMs) {
            outErr = "超时未捕获到数据库密钥（用户未完成登录？断点未触发？）";
            break;
        }

        int status = 0;
        // 全局 WNOHANG 轮询而非阻塞等待：事件在队列里不会丢，无事件时小睡，
        // 从而保证 RequestStop()/超时 在微信空闲时也能生效。
        const pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);
        if (tid == 0) {
            usleep(3000);
            continue;
        }
        if (tid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            outErr = ErrnoDesc("waitpid(-1) 失败");
            break;
        }

        g_log.Log("Capture: waitpid(-1)->%d status=0x%x sig=%d ev=%d", (int)tid, status,
                  WIFSTOPPED(status) ? WSTOPSIG(status) : -1,
                  WIFSTOPPED(status) ? ((status >> 16) & 0xffff) : -1);
        if (WIFSTOPPED(status)) {
            siginfo_t si{};
            if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &si) == 0) {
                g_log.Log("  siginfo: si_code=%d si_pid=%d", si.si_code, si.si_pid);
            } else {
                g_log.Log("  GETSIGINFO failed errno=%d", errno);
            }
            struct user_regs_struct rg{};
            if (ptrace(PTRACE_GETREGS, tid, nullptr, &rg) == 0) {
                g_log.Log("  rip=0x%llx rax=0x%llx rdi=0x%llx rsi=0x%llx",
                          (unsigned long long)rg.rip, (unsigned long long)rg.rax,
                          (unsigned long long)rg.rdi, (unsigned long long)rg.rsi);
            } else {
                g_log.Log("  GETREGS failed errno=%d", errno);
            }
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            tids_.erase(tid);
            armedTids_.erase(tid);
            g_log.Log("Capture: tid %d exited, %zu left", (int)tid, tids_.size());
            if (tids_.count(childPid_) == 0) {
                outErr = "微信主线程已退出（进程退出了？）";
                break;
            }
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        // 新线程的第一次 stop：在这里补装断点。此时它必定处于 ptrace 停止态，
        // POKEUSER 不会失败（在父线程的 clone 事件上装则会大量失败，见上）。
        if (armedTids_.count(tid) == 0) {
            tids_.insert(tid);
            const bool ok = SetHwBp(tid);
            armedTids_.insert(tid);
            g_log.Log("Capture: arm-on-first-stop tid=%d ok=%d", (int)tid, (int)ok);
        }

        const int sig = WSTOPSIG(status);
        const int event = (status >> 16) & 0xffff;

        if (sig == SIGTRAP && event == PTRACE_EVENT_CLONE) {
            unsigned long newTid = 0;
            ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &newTid);
            // DR 健康度：父线程（通常就是主线程，在 exec-stop 就装过断点）此刻的
            // DR0/DR7 若已变 0/0xffffffffffffffff，说明断点被清掉了（例如目标自行
            // re-exec 走了内核 flush_thread），这是"断点在手却永远不命中"的头号嫌疑。
            if (cloneLogCount_++ < 3) {
                const unsigned long h0 =
                    ptrace(PTRACE_PEEKUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[0])), nullptr);
                const unsigned long h7 =
                    ptrace(PTRACE_PEEKUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[7])), nullptr);
                g_log.Log("  DR health(parent tid=%d): DR0=0x%lx DR7=0x%lx (want 0x%lx/0x1)", (int)tid, h0, h7,
                          (unsigned long)bpAddr_);
            }
            if (newTid > 0) {
                const pid_t nt = static_cast<pid_t>(newTid);
                tids_.insert(nt);
                ptrace(PTRACE_SETOPTIONS, nt, nullptr,
                       reinterpret_cast<void*>(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                                               PTRACE_O_EXITKILL));
                // ❗不在这里装断点、也不在这里 CONT。
                // 在父线程的 clone 事件上对新线程 POKEUSER 会大量失败（实测 94 个新
                // 线程里 25 个 SetHwBp 返回失败，EESRCH——新线程此刻还不一定能被
                // 我们 poke），静默失败就意味着那个线程全程无断点。改为等它自己的
                // 第一次 stop（下面 arm-on-first-stop），那时它必定处于停止态。
                g_log.Log("Capture: clone -> tid %d pending (arm on its own stop)", (int)nt);
            }
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            continue;
        }

        if (sig == SIGTRAP && event == PTRACE_EVENT_EXEC) {
            // execve 会走内核 flush_thread()，调试寄存器（DR0/DR7）会被清空。
            // 自启动方案在 exec-stop 就布防，一旦目标自行 re-exec，断点会静默消失，
            // 所以必须在这里重新布防。（Xkey 是 attach 已运行的进程，不会遇到此窗口。）
            if (armed_ && bpAddr_ != 0) {
                SetHwBp(tid);
                armedTids_.insert(tid);
            }
            g_log.Log("Capture: PTRACE_EVENT_EXEC -> 已重新布防 DR0 tid=%d", (int)tid);
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            continue;
        }

        if (sig == SIGTRAP) {
            struct user_regs_struct regs{};
            if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == 0) {
                const long long delta = static_cast<long long>(regs.rip) - static_cast<long long>(bpAddr_);
                if (regs.rip == bpAddr_) {
                    g_log.Log("*** DR0 HIT *** tid=%d rip=0x%llx rdi=0x%llx rsi=0x%llx rdx=0x%llx", (int)tid,
                              (unsigned long long)regs.rip, (unsigned long long)regs.rdi,
                              (unsigned long long)regs.rsi, (unsigned long long)regs.rdx);
                    if (TryReadKey(tid, regs, outKeyHex)) {
                        captured = true;
                        hitTid = tid;
                        break;
                    }
                    // 命中但布局不符（非目标调用）：单步越过本条指令后重新布防
                    g_log.Log("  hit rejected by TryReadKey -> 单步重布防");
                    ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr);
                    int st2 = 0;
                    waitpid(tid, &st2, __WALL);
                    SetHwBp(tid);
                } else if (delta > -0x4000 && delta < 0x4000) {
                    // 断点附近的其他 SIGTRAP：可用于判断"地址差一点"还是"函数压根没被调用"
                    g_log.Log("*** DR0 NEAR *** tid=%d rip=0x%llx bp=0x%llx delta=%lld", (int)tid,
                              (unsigned long long)regs.rip, (unsigned long long)bpAddr_, delta);
                }
            }
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            continue;
        }

        // 其余信号：SIGSTOP 组停止不注入，其他透传给微信
        const long inject = (sig == SIGSTOP) ? 0 : sig;
        if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(inject)) != 0) {
            g_log.Log("  CONT(sig=%ld) FAILED errno=%d", inject, errno);
        } else {
            g_log.Log("  CONT(sig=%ld) ok", inject);
        }
    }

    if (captured) {
        hitTid_ = hitTid;
        DetachAll();
        return true;
    }
    if (stop_.load()) {
        outErr = "已请求停止";
    }
    hitTid_ = -1;
    DetachAll();
    return false;
}

void LinuxHooker::RequestStop() { stop_ = true; }

bool LinuxHooker::DetachAll() {
    if (childPid_ <= 0) {
        tids_.clear();
        return true;
    }
    const pid_t pid = childPid_;

    // 1. SIGSTOP 全部线程（命中线程已在 ptrace-stop，SIGSTOP 挂起即可）
    for (const pid_t t : tids_) {
        if (t != hitTid_) syscall(SYS_tgkill, pid, t, SIGSTOP);
    }

    // 2. 等每个线程停住（上限 ~1s）；命中线程已停，无需等待
    for (const pid_t t : tids_) {
        if (t == hitTid_) continue;
        int attempts = 0;
        for (;;) {
            int st = 0;
            const pid_t r = waitpid(t, &st, __WALL | WNOHANG);
            if (r == t) break;
            if (r < 0 && (errno == ECHILD || errno == ESRCH)) break;
            if (++attempts > 100) break;  // 罕见：卡在不可中断状态的线程，放弃等待
            usleep(10 * 1000);
        }
    }

    // 3. 清断点 + detach（PTRACE_DETACH 会恢复 tracee）
    for (const pid_t t : tids_) {
        ClearHwBp(t);
        ptrace(PTRACE_DETACH, t, nullptr, nullptr);
    }

    // 4. 收尾清扫：捕获循环退出瞬间可能还有未入集合的 CLONE stop
    for (int i = 0; i < 50; ++i) {
        int st = 0;
        const pid_t r = waitpid(-1, &st, __WALL | WNOHANG);
        if (r <= 0) break;
        if (WIFSTOPPED(st)) {
            ClearHwBp(r);
            ptrace(PTRACE_DETACH, r, nullptr, nullptr);
        }
    }

    tids_.clear();
    armedTids_.clear();
    armed_ = false;

    // 5. 群停的线程需要 SIGCONT 恢复 —— 微信继续登录流程
    kill(pid, SIGCONT);

    childPid_ = -1;
    hitTid_ = -1;
    return true;
}

bool LinuxHooker::ReadMemory(uintptr_t addr, void* buffer, size_t size) {
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    const ssize_t n = process_vm_readv(childPid_, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

std::string LinuxHooker::HexEncode(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

bool LinuxHooker::SetHwBp(pid_t tid) {
    // DR0 = 断点地址；DR7 低字节 0x01（L0：本地执行断点，LEN=00/RW=00）
    if (ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[0])),
               reinterpret_cast<void*>(bpAddr_)) < 0) {
        return false;
    }
    if (ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[7])),
               reinterpret_cast<void*>(static_cast<uintptr_t>(0x1))) < 0) {
        return false;
    }
    return true;
}

bool LinuxHooker::ClearHwBp(pid_t tid) {
    ptrace(PTRACE_POKEUSER, tid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[7])),
           reinterpret_cast<void*>(static_cast<uintptr_t>(0)));
    return true;
}