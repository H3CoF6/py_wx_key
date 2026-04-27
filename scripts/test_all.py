import sys
import time
import json
import psutil
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner

try:
    import wx_key
except ImportError:
    print("[!] 无法导入 wx_key 模块，请确保编译成功。")
    sys.exit(1)

console = Console()

# ================= 配置区域 =================
# 如果要测试“双路 Hook”模式，请填写图片特征码
MD5_PATTERN = "48 8D 4D 00 48 89 4D B0 48 89 45 B8 48 8D 7D 00 48 8D 55 B0 48 89 F9"
MD5_MASK = "xxx?xxxxxxxxxxx?xxxxxxx"
MD5_OFFSET = 4
# ===========================================

def get_wechat_pid():
    candidates = ['WeChat.exe', 'weixin.exe']
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] and proc.info['name'].lower() in [c.lower() for c in candidates]:
            return proc.info['pid'], proc.info['name']
    return None, None

def main():
    pid, proc_name = get_wechat_pid()
    if not pid:
        console.print("[bold red]❌ 未找到运行中的 WeChat.exe 或 weixin.exe 进程。[/bold red]")
        return

    title = Text("WeChat All-in-One Key Capture Demo", justify="center", style="bold magenta")
    console.print(Panel(title, border_style="blue"))
    console.print(f"[bold green]目标进程: {proc_name} (PID: {pid})[/bold green]")

    # 1. 演示【本地文件算法提取】(无需 Hook)
    console.print("\n[bold yellow][1/3] 正在执行本地算法提取 (无需注入/无需 Hook)...[/bold yellow]")
    img_key_json = wx_key.get_image_key()
    if img_key_json:
        data = json.loads(img_key_json)
        table = Table(title="本地提取的图片密钥 (AES/XOR)", show_header=True, header_style="bold green")
        table.add_column("wxid", style="cyan")
        table.add_column("XOR Key", style="yellow")
        table.add_column("AES Key (16-char)", style="green")
        for account in data.get('accounts', []):
            wxid = account.get('wxid', 'unknown')
            for k in account.get('keys', []):
                table.add_row(wxid, str(k.get('xorKey')), k.get('aesKey'))
        console.print(table)
    else:
        console.print("[red]未在本地找到图片密钥信息。[/red]")

    # 2. 演示【数据库密钥自动 Hook】(单 PID 调用)
    console.print(f"\n[bold yellow][2/3] 正在初始化数据库密钥自动 Hook (仅传入 PID: {pid})...[/bold yellow]")
    if wx_key.initialize_hook(pid):
        console.print("[green]✅ 数据库密钥 Hook 已安装成功。[/green]")
        # 轮询一会儿看看能不能拿到
        console.print("[dim]轮询数据库密钥 (请在微信执行登录操作)...[/dim]")
        while True:
            res = wx_key.poll_key_data()
            if res and 'key' in res:
                console.print(Panel(f"[green bold]{res['key']}[/]", title="🔑 捕获: 数据库密钥"))
                break
            time.sleep(0.1)
        wx_key.cleanup_hook()
    else:
        console.print(f"[red]❌ 初始化失败: {wx_key.get_last_error_msg()}[/red]")

    # 3. 演示【双路 Hook 模式】(全参数调用)
    # console.print(f"\n[bold yellow][3/3] 正在初始化双路 Hook (数据库自动 + 图片手动特征码)...[/bold yellow]")
    # if wx_key.initialize_hook(pid, MD5_PATTERN, MD5_MASK, MD5_OFFSET):
    #     console.print("[green]✅ 双路 Hook 已安装成功。[/green]")
    #     try:
    #         with Live(Spinner("dots", text="等待触发 Hook (按 Ctrl+C 退出)...", style="magenta"), refresh_per_second=10) as live:
    #             while True:
    #                 # 打印后台日志
    #                 msg, level = wx_key.get_status_message()
    #                 while msg:
    #                     live.stop()
    #                     console.print(f"[*] Backend: {msg}")
    #                     live.start()
    #                     msg, level = wx_key.get_status_message()
    #
    #                 # 轮询捕获
    #                 res = wx_key.poll_key_data()
    #                 if res:
    #                     live.stop()
    #                     if 'key' in res:
    #                         console.print(Panel(f"[green bold]{res['key']}[/]", title="🔑 捕获: DB Key"))
    #                     if 'md5' in res:
    #                         console.print(Panel(f"[yellow bold]{res['md5']}[/]", title="📦 捕获: Image Hook Data"))
    #                     live.start()
    #                 time.sleep(0.1)
    #     except KeyboardInterrupt:
    #         pass
    #     finally:
    #         wx_key.cleanup_hook()
    #         console.print("[bold green]✅ Hook 已卸载。[/bold green]")
    # else:
    #     console.print(f"[red]❌ 双路初始化失败: {wx_key.get_last_error_msg()}[/red]")

if __name__ == "__main__":
    main()
