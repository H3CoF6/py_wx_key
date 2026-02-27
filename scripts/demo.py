import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner

try:
    import wx_key
except ImportError:
    print("[!] 无法导入 wx_key 模块，请确保编译成功且 .pyd 文件在当前目录。")
    sys.exit(1)

# 初始化 Rich 控制台
console = Console()

# ================= 配置区域 =================
# 1. 目标微信进程 PID (任务管理器中查看)
TARGET_PID = 29536

KEY_PATTERN = "24 08 48 89 6c 24 10 48 89 74 00 18 48 89 7c 00 20 41 56 48 83 ec 50 41"
KEY_MASK = "xxxxxxxxxx?xxxx?xxxxxxxx"
KEY_OFFSET = -3

MD5_PATTERN = "48 8D 4D 00 48 89 4D B0 48 89 45 B8 48 8D 7D 00 48 8D 55 B0 48 89 F9"
MD5_MASK = "xxx?xxxxxxxxxxx?xxxxxxx"
MD5_OFFSET = 4

# ===========================================

def print_header():
    """打印华丽的启动横幅和配置信息"""
    title = Text("WeChat Dual-Hook System (DB Key + Image Key)", justify="center", style="bold magenta")

    table = Table(show_header=False, expand=True, border_style="cyan")
    table.add_column("Property", style="bold cyan", width=20)
    table.add_column("Value", style="green")

    table.add_row("Target PID", str(TARGET_PID))
    table.add_row("DB Key Pattern", f"{KEY_PATTERN[:30]}...")
    table.add_row("Image Key Pattern", f"{MD5_PATTERN[:30]}...")
    table.add_row("Hook Strategy", "Inline Hook (Trampoline) + Stack Spoofing")
    table.add_row("IPC Method", "Shared Memory Polling (No injected threads)")

    panel = Panel(table, title=title, border_style="blue", padding=(1, 2))
    console.print(panel)


def poll_logs():
    """抽取并打印 C++ 后端的内部状态日志"""
    while True:
        msg, level = wx_key.get_status_message()
        if msg is None:
            break

        # 0=Info, 1=Success, 2=Error
        if level == 0:
            console.print(f"[dim cyan][*] Backend:[/dim cyan] {msg}")
        elif level == 1:
            console.print(f"[bold green][+] Backend:[/bold green] {msg}")
        elif level == 2:
            console.print(f"[bold red][!] Backend ERROR:[/bold red] {msg}")


def display_captured_data(data_type, data_value):
    """华丽地展示捕获到的数据"""
    if data_type == "key":
        title = "🔑 成功捕获: 数据库解密密钥 (DB Key)"
        color = "green"
    else:
        title = "📦 成功捕获: 图片解密密钥 (MD5)"
        color = "yellow"

    content = f"[{color} bold]{data_value}[/]\n\n[dim]你现在可以使用此数据进行后续操作。[/]"
    console.print(Panel(content, title=title, border_style=color, expand=False))


def main():
    print_header()

    console.print("\n[bold yellow][*] 正在向目标进程注入双 Hook...[/bold yellow]")

    # -----------------------------------------------------------
    # 1. 初始化双 Hook (传入两组特征码)
    # -----------------------------------------------------------
    success = wx_key.initialize_hook(
        TARGET_PID,
        "",  # 版本号留空，不强制校验
        KEY_PATTERN, KEY_MASK, KEY_OFFSET,
        MD5_PATTERN, MD5_MASK, MD5_OFFSET
    )

    # 立即拉取初始化过程中的日志
    poll_logs()

    if not success:
        err = wx_key.get_last_error_msg()
        console.print(f"\n[bold red]❌ Hook 初始化失败: {err}[/bold red]")
        console.print("[dim]提示: 请检查 PID 是否正确，特征码是否匹配当前版本，以及是否以【管理员身份】运行。[/dim]")
        return

    console.print("\n[bold green]✅ Hook 系统已启动并挂载！[/bold green]")
    console.print("[cyan]原理说明:[/cyan]")
    console.print("  1. [dim]已在目标内存开辟共享内存区用于 IPC 通信。[/dim]")
    console.print("  2. [dim]已精准定位核心函数，拦截相关寄存器参数。[/dim]")
    console.print("  3. [dim]当前处于轮询等待状态，请在微信中执行【登录】或【解锁】操作触发函数。[/dim]\n")

    # 记录是否已经抓到数据
    captured_key = False
    captured_md5 = False

    try:
        # 使用 rich 的 Spinner 制作等待动画
        with Live(Spinner("dots", text="等待用户在微信中操作触发 Hook... (按 Ctrl+C 退出)", style="magenta"),
                  refresh_per_second=10) as live:
            while True:
                # -----------------------------------------------------------
                # 2. 轮询内部日志
                # -----------------------------------------------------------
                msg, level = wx_key.get_status_message()
                while msg is not None:
                    live.stop()
                    if level == 0:
                        console.print(f"[dim cyan][*] Backend:[/dim cyan] {msg}")
                    elif level == 1:
                        console.print(f"[bold green][+] Backend:[/bold green] {msg}")
                    elif level == 2:
                        console.print(f"[bold red][!] Backend ERROR:[/bold red] {msg}")
                    live.start()
                    msg, level = wx_key.get_status_message()

                # -----------------------------------------------------------
                # 3. 轮询 Hook 截获的数据
                # -----------------------------------------------------------
                result = wx_key.poll_key_data()

                if result:
                    live.stop()  # 停止加载动画

                    if 'key' in result:
                        display_captured_data("key", result['key'])
                        captured_key = True

                    if 'md5' in result:
                        display_captured_data("md5", result['md5'])
                        captured_md5 = True

                    # 当两个密钥都拿到后，直接退出循环，准备卸载 Hook
                    if captured_key and captured_md5:
                        console.print("\n[bold green]🎉 恭喜！数据库密钥与图片密钥已全部收集完毕！[/bold green]")
                        break

                    live.start()  # 恢复加载动画

                time.sleep(0.05)  # 50ms 轮询一次，兼顾性能与响应速度

    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] 收到中断信号，准备退出...[/bold yellow]")

    finally:
        # -----------------------------------------------------------
        # 4. 安全卸载 Hook
        # -----------------------------------------------------------
        console.print("[*] 正在清理内存并还原目标进程的指令集...")
        wx_key.cleanup_hook()
        console.print("[bold green]✅ 资源释放完毕，安全退出。[/bold green]")


if __name__ == "__main__":
    main()