// 假目标 + 真 ptrace 单元测试：
//   Spawn(fake_wechat) -> bias + sinkVA -> ArmBreakpoint -> RunCapture -> 校验 32 字节 hex
// 用法: test_hooker <fake_wechat_path> <sink_va_hex>
//   sink VA 用 nm 取：nm build/linux/fake_wechat | grep sink_write_config
//   （与生产路径同语义：绝对地址 = 加载基址 + ELF VA）
#include "../include/linux_hooker.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: test_hooker <fake_wechat_path> <sink_va_hex>\n");
        return 2;
    }
    const std::string fakePath = argv[1];
    const uintptr_t sinkVA = std::stoull(argv[2], nullptr, 16);

    LinuxHooker hooker;
    std::string err;

    // ❗必须在 RunCapture 之前记下 pid：RunCapture 结束后内部 DetachAll() 会把
    // childPid() 置为 -1，若拿它做收尾判断会恒假，假目标就变成孤儿进程——
    // 而孤儿会握着调用方的 stdout 管道不放（ctest / `| head` 会全部卡死）。
    pid_t childPid = -1;
    auto cleanup = [&] {
        if (childPid > 0) {
            kill(childPid, SIGKILL);
            int st = 0;
            waitpid(childPid, &st, __WALL);
            childPid = -1;
        }
    };

    // 1. TRACEME 自启动（与生产一致：不传 addr 文件）
    if (!hooker.Spawn(fakePath, {fakePath}, err)) {
        std::fprintf(stderr, "FAIL spawn: %s\n", err.c_str());
        return 1;
    }
    childPid = hooker.childPid();
    std::fprintf(stderr, "[test] spawned pid=%d\n", static_cast<int>(childPid));

    // 2. 解析加载基址（子进程停在 exec-stop，尚未执行任何指令）
    const uintptr_t bias = hooker.ResolveLoadBias(err);
    if (bias == 0) {
        std::fprintf(stderr, "FAIL bias: %s\n", err.c_str());
        cleanup();
        return 1;
    }
    std::fprintf(stderr, "[test] load bias = 0x%lx\n", static_cast<unsigned long>(bias));

    // 3. 绝对地址 = bias + VA（生产里 VA 来自 LinuxScanner 锚点推导）
    const uintptr_t sinkAddr = bias + sinkVA;
    std::fprintf(stderr, "[test] sink = 0x%lx\n", static_cast<unsigned long>(sinkAddr));

    // 4. 布防 + 捕获（假目标在子线程里触发 sink）
    if (!hooker.ArmBreakpoint(sinkAddr, err)) {
        std::fprintf(stderr, "FAIL arm: %s\n", err.c_str());
        cleanup();
        return 1;
    }

    std::string keyHex;
    if (!hooker.RunCapture(15000, keyHex, err)) {
        std::fprintf(stderr, "FAIL capture: %s\n", err.c_str());
        cleanup();
        return 1;
    }

    // 5. 校验 32 字节 hex（与 fake_wechat.cpp 的 key 数组一致）
    const char* expected = "deadbeef0123456789abcdeffedcba9800112233445566778899aabbccddeeff";
    if (keyHex != expected) {
        std::fprintf(stderr, "FAIL key mismatch\n  got:      %s\n  expected: %s\n",
                     keyHex.c_str(), expected);
        cleanup();
        return 1;
    }
    std::printf("PASS: captured key %s\n", keyHex.c_str());

    // 结束假微信（RunCapture 已 detach，这里显式回收子进程）
    cleanup();
    return 0;
}