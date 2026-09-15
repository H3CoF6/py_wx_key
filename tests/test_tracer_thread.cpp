// 回归测试：ptrace 的**线程亲和性**。
//
// fork+PTRACE_TRACEME 建立起的跟踪关系绑定在**执行 fork 的那个线程**上；此后对该
// tracee 的 ptrace 请求（GETREGS/CONT/…）必须由同一线程发起。其他线程调用会收到
// ESRCH(errno 3)，而 waitpid 仍能正常收到 stop 事件 —— 这个组合正是当初
// "微信停住不动、窗口不出现、日志里 waitpid 有事件但 CONT 全 ESRCH" 的根因。
//
//   A: fork 与 ptrace 在同一线程   → 必须成功（本实现的前提）
//   B: fork 在线程 1，ptrace 在线程 2 → 观察项（预期 ESRCH；若某内核放宽了此限制，
//      对我们无害，故只打印不断言）
//
// 退出码：A 失败则返回 1。
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <thread>

int main() {
    bool aOk = false;
    printf("== A: fork 与 ptrace 在同一线程 ==\n");
    {
        pid_t pid = fork();
        if (pid == 0) {
            ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            execl("/bin/true", "true", (char*)nullptr);
            _exit(127);
        }
        int st = 0;
        waitpid(pid, &st, __WALL);
        struct user_regs_struct rg{};
        errno = 0;
        const long r = ptrace(PTRACE_GETREGS, pid, nullptr, &rg);
        aOk = (r == 0);
        printf("  GETREGS -> ret=%ld errno=%d (%s)\n", r, errno, strerror(errno));
        ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        waitpid(pid, &st, __WALL);
    }

    printf("== B: fork 在线程 A，waitpid/ptrace 在线程 B（曾经的错误结构） ==\n");
    {
        pid_t pid = -1;
        std::thread forker([&] {
            pid = fork();
            if (pid == 0) {
                ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
                execl("/bin/sleep", "sleep", "1", (char*)nullptr);
                _exit(127);
            }
            // 用同一线程等 exec-stop（与生产一致）
            int st = 0;
            waitpid(pid, &st, __WALL);
        });
        forker.join();

        int st = 0;
        const pid_t got = waitpid(-1, &st, __WALL);  // 线程 B：全局等待，可看到 stop
        printf("  waitpid(-1) -> pid=%d status=0x%x\n", (int)got, st);
        errno = 0;
        struct user_regs_struct rg{};
        const long r = ptrace(PTRACE_GETREGS, pid, nullptr, &rg);
        printf("  GETREGS -> ret=%ld errno=%d (%s)\n", r, errno, strerror(errno));
        errno = 0;
        const long c = ptrace(PTRACE_CONT, pid, nullptr, nullptr);
        printf("  CONT    -> ret=%ld errno=%d (%s)\n", c, errno, strerror(errno));
        kill(pid, SIGKILL);
        waitpid(pid, &st, __WALL);
    }

    if (!aOk) {
        printf("FAIL: 同线程 ptrace 竟然失败——本实现的线程模型前提不成立\n");
        return 1;
    }
    printf("PASS: 同线程 ptrace 正常（Spawn/Arm/RunCapture/DetachAll 必须同线程）\n");
    return 0;
}
