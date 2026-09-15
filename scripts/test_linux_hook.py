#!/usr/bin/env python3
"""Linux 数据库密钥自测：拉起微信 -> 扫码登录 -> 捕获 64-hex 数据库密钥。

本地迭代用（不是产品代码）。用法：
    PYTHONPATH=packaging python3 scripts/test_linux_hook.py [--no-kill] [--timeout 180]

流程与 Windows 一致：先结束已运行的微信（触发重新登录），再由 wx_key 自行
TRACEME 拉起，登录 PBKDF 命中断点时自动取参。AppImage 微信通过 FUSE 挂载，
root 不可见 —— 本脚本及 wx_key 都保持普通用户运行，绝不用 sudo/pkexec。
"""
import argparse
import os
import subprocess
import sys
import time


def find_wechat() -> str:
    for cand in (os.environ.get("WECHAT_BIN"), "/usr/bin/wechat", "/opt/wechat/wechat"):
        if cand and os.path.exists(cand):
            return cand
    raise SystemExit("找不到微信二进制（可设 WECHAT_BIN）")


def kill_running_wechat() -> None:
    try:
        out = subprocess.run(["pgrep", "-x", "wechat"], capture_output=True, text=True)
    except FileNotFoundError:
        return
    pids = [int(x) for x in out.stdout.split()]
    if not pids:
        return
    print(f"[!] 微信正在运行 (pid={pids})，先结束以触发重新登录（与 Windows 流程一致）")
    subprocess.run(["pkill", "-TERM", "-x", "wechat"], check=False)
    time.sleep(2)
    # 兜底：没退干净就 SIGKILL
    out = subprocess.run(["pgrep", "-x", "wechat"], capture_output=True, text=True)
    if out.stdout.strip():
        subprocess.run(["pkill", "-KILL", "-x", "wechat"], check=False)
        time.sleep(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-kill", action="store_true", help="不结束已运行的微信")
    ap.add_argument("--timeout", type=int, default=180, help="轮询超时（秒）")
    args = ap.parse_args()

    wechat = find_wechat()
    if not args.no_kill:
        kill_running_wechat()
    else:
        print("[i] --no-kill：不会结束已运行的微信")

    import wx_key  # noqa: E402  (PYTHONPATH=packaging)

    print(f"[*] initialize_hook({wechat})")
    if not wx_key.initialize_hook(wechat):
        print(f"[x] 初始化失败: {wx_key.get_last_error_msg()}")
        return 1

    print("[*] 微信已由 wx_key 拉起，请在微信窗口中扫码/登录 ...", flush=True)
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        msg = wx_key.poll_key_data()
        if msg and msg.get("key"):
            print(f"\n[DB KEY] {msg['key']}", flush=True)
            wx_key.cleanup_hook()
            return 0
        st = wx_key.get_status_message()
        while st[0] is not None:
            print(f"  [status] {st}", flush=True)
            st = wx_key.get_status_message()
        time.sleep(0.2)

    print("[x] 超时未捕获到数据库密钥")
    wx_key.cleanup_hook()
    return 1


if __name__ == "__main__":
    sys.exit(main())