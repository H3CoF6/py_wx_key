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

console = Console()

# ================= 配置区域 =================
TARGET_PID = 29260

KEY_PATTERN = "24 08 48 89 6c 24 10 48 89 74 00 18 48 89 7c 00 20 41 56 48 83 ec 50 41"
KEY_MASK = "xxxxxxxxxx?xxxx?xxxxxxxx"
KEY_OFFSET = -3

MD5_PATTERN = "48 8D 4D 00 48 89 4D B0 48 89 45 B8 48 8D 7D 00 48 8D 55 B0 48 89 F9"
MD5_MASK = "xxx?xxxxxxxxxxx?xxxxxxx"
MD5_OFFSET = 4


# ===========================================

def print_header():
    title = Text("WeChat Dual-Hook System (DB Key + Image Key)", justify="center", style="bold magenta")
    table = Table(show_header=False, expand=True, border_style="cyan")
    table.add_column("Property", style="bold cyan", width=20)
    table.add_column("Value", style="green")
    table.add_row("Target PID", str(TARGET_PID))
    table.add_row("DB Key Pattern", f"{KEY_PATTERN[:30]}...")
    table.add_row("Image Key Pattern", f"{MD5_PATTERN[:30]}...")
    table.add_row("Hook Strategy", "Inline Hook (Trampoline) + Stack Spoofing")
    table.add_row("IPC Method", "Shared Memory Polling (No injected threads)")
    console.print(Panel(table, title=title, border_style="blue", padding=(1, 2)))


def display_captured_data(data_type, data_value):
    if data_type == "key":
        title = "🔑 成功捕获: 数据库解密密钥 (DB Key)"
        color = "green"
        content = f"[{color} bold]{data_value}[/]\n\n[dim]用于解密 .db 数据库文件。[/]"
    else:
        title = "📦 成功捕获: 图片解密参数 (Image Key)"
        color = "yellow"
        # 分割 C++ 传回来的 "MD5_16位|XOR密钥"
        md5_16, xor_key = data_value.split('|')
        content = (f"[{color} bold]MD5 (16位):[/] {md5_16}\n"
                   f"[{color} bold]异或密钥 (XOR):[/] {xor_key}\n\n"
                   f"[dim]用于解密 .dat 图片文件 (利用 XOR 密钥进行异或还原)。[/]")

    console.print(Panel(content, title=title, border_style=color, expand=False))


def main():
    print_header()
    console.print("\n[bold yellow][*] 正在向目标进程注入双 Hook...[/bold yellow]")

    success = wx_key.initialize_hook(
        TARGET_PID, "", KEY_PATTERN, KEY_MASK, KEY_OFFSET, MD5_PATTERN, MD5_MASK, MD5_OFFSET
    )

    msg, level = wx_key.get_status_message()
    while msg is not None:
        console.print(
            f"[{'dim cyan' if level == 0 else 'bold green' if level == 1 else 'bold red'}][*] Backend:[/] {msg}")
        msg, level = wx_key.get_status_message()

    if not success:
        console.print(f"\n[bold red]❌ Hook 初始化失败: {wx_key.get_last_error_msg()}[/bold red]")
        return

    console.print("\n[bold green]✅ Hook 系统已启动并挂载！请在微信中执行登录或解锁操作。[/bold green]\n")

    captured_key = False
    captured_md5 = False

    try:
        with Live(Spinner("dots", text="等待触发 Hook... (按 Ctrl+C 退出)", style="magenta"),
                  refresh_per_second=10) as live:
            while True:
                msg, level = wx_key.get_status_message()
                while msg is not None:
                    live.stop()
                    console.print(
                        f"[{'dim cyan' if level == 0 else 'bold green' if level == 1 else 'bold red'}][*] Backend:[/] {msg}")
                    live.start()
                    msg, level = wx_key.get_status_message()

                result = wx_key.poll_key_data()
                if result:
                    live.stop()
                    if 'key' in result:
                        display_captured_data("key", result['key'])
                        captured_key = True
                    if 'md5' in result:
                        display_captured_data("md5", result['md5'])
                        captured_md5 = True

                    # 两个数据都拿到后，直接跳出循环
                    if captured_key and captured_md5:
                        console.print("\n[bold green]🎉 恭喜！数据库密钥与图片解密参数已全部收集完毕！[/bold green]")
                        break
                    live.start()
                time.sleep(0.05)

    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] 收到中断信号，准备退出...[/bold yellow]")
    finally:
        console.print("[*] 正在清理内存并还原目标进程的指令集...")
        wx_key.cleanup_hook()
        console.print("[bold green]✅ 资源释放完毕，Hook 已安全卸载。[/bold green]")


if __name__ == "__main__":
    main()