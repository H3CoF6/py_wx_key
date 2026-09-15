// 锚点推导自测：对指定 ELF 跑 LinuxScanner，打印 sink VA。
// 用法: test_scanner <wechat_binary>
#include "../include/linux_scanner.h"

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_scanner <wechat_binary>\n");
        return 2;
    }
    LinuxScanner scanner;
    ScanResult result;
    if (!scanner.SearchForHookAddress(argv[1], result)) {
        std::fprintf(stderr, "FAIL: %s\n", result.msg.c_str());
        return 1;
    }
    std::printf("PASS: sink VA = 0x%lx (%s)\n",
                static_cast<unsigned long>(result.targetVA), result.msg.c_str());
    return 0;
}