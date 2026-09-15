// 假微信：内存布局与真实 sink 一致的"配置写入"函数。
// 用于在不启动真实微信的情况下验证 TRACEME 自启动 + DR0 断点 + 参数读取全链路。
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <unistd.h>

// 与真实目标一致的内存布局：
//   rsi + 0x08 -> const uint8_t* key（32 字节）
//   rsi + 0x10 -> uint32_t keyLen
struct CipherConfig {
    uint8_t pad[8];
    const uint8_t* key;
    uint32_t keyLen;
    uint32_t reserved;
};

// 与真实 sink 一致：配置对象在第二个参数（SysV ABI -> rsi），
// hooker 读 rsi+0x08（key 指针）/ rsi+0x10（keyLen）。
extern "C" __attribute__((noinline)) void sink_write_config(void* reserved, CipherConfig* cfg) {
    volatile uint32_t len = cfg->keyLen;
    volatile const uint8_t* k = cfg->key;
    (void)len;
    (void)k;
    (void)reserved;
}

int main(int argc, char** argv) {
    // argv[1] 仅作可选调试输出（正常测试通过 nm 取 sink VA，与生产路径同语义）
    (void)argc;
    (void)argv;

    // 给 tracer 一点时间布防断点（真实场景布防发生在 exec-stop，此 sleep 模拟"登录前的启动耗时"）
    usleep(300 * 1000);

    static uint8_t key[32] = {
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    CipherConfig cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.key = key;
    cfg.keyLen = 32;

    // 在一个**子线程**里调用 sink：真实微信的密钥派生也发生在 worker 线程上。
    // 这样会走 PTRACE_EVENT_CLONE + "新线程首次 stop 时补装断点"（arm-on-first-stop）
    // 这条路径——之前正是在这里静默失败（94 个新线程里 25 个没装上断点）。
    std::thread worker([&cfg] {
        usleep(200 * 1000);
        sink_write_config(nullptr, &cfg);
    });
    worker.join();

    // 保持存活，模拟"捕获完成后微信继续运行"；tracer detach 后本进程恢复独立
    for (;;) pause();
    return 0;
}