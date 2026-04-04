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
    print("[!] 无法导入 wx_key 模块，请确保编译成功且 .pyd 文件在当前目录。")
    sys.exit(1)

console = Console()

def get_wechat_pid():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == 'wechat.exe':
            return proc.info['pid']
    return None

def print_header(pid):
    title = Text("WeChat Hook System (Auto Scanning)", justify="center", style="bold magenta")
    table = Table(show_header=False, expand=True, border_style="cyan")
    table.add_column("Property", style="bold cyan", width=20)
    table.add_column("Value", style="green")
    table.add_row("Target PID", str(pid))
    table.add_row("Mode", "Auto Scanning (No manual patterns)")
    table.add_row("Hook Strategy", "Inline Hook + Stack Spoofing")
    table.add_row("Image Key", "Local File Extraction (MMKV/Statistic)")
    console.print(Panel(table, title=title, border_style="blue", padding=(1, 2)))

def display_captured_key(key):
    title = "🔑 成功捕获: 数据库解密密钥 (DB Key)"
    color = "green"
    content = f"[green bold]{key}[/]\n\n[dim]用于解密 .db 数据库文件。[/]"
    console.print(Panel(content, title=title, border_style=color, expand=False))

def display_image_keys():
    console.print("\n[bold yellow][*] 正在扫描本地文件提取图片密钥...[/bold yellow]")
    img_key_json = wx_key.get_image_key()
    if img_key_json:
        try:
            data = json.loads(img_key_json)
            title = "📦 本地提取: 图片解密参数 (Image Keys)"
            
            table = Table(show_header=True, header_style="bold magenta", border_style="yellow")
            table.add_column("微信ID (wxid)", style="cyan")
            table.add_column("唯一码 (Code)", style="dim")
            table.add_column("XOR 密钥", style="bold yellow")
            table.add_column("AES 密钥 (16位)", style="bold green")
            
            for account in data.get('accounts', []):
                wxid = account.get('wxid', 'unknown')
                for k in account.get('keys', []):
                    table.add_row(
                        wxid, 
                        str(k.get('code')), 
                        str(k.get('xorKey')), 
                        k.get('aesKey')
                    )
            
            console.print(Panel(table, title=title, border_style="yellow", padding=(1, 1)))
        except Exception as e:
            console.print(f"[bold red]❌ 解析图片密钥 JSON 失败: {e}[/bold red]")
    else:
        console.print("[bold red]❌ 未能提取到图片密钥信息。[/bold red]")

def main():
    target_pid = get_wechat_pid()
    if not target_pid:
        console.print("[bold red]❌ 未找到运行中的 WeChat.exe 进程。[/bold red]")
        return

    print_header(target_pid)
    
    # 1. 显示图片密钥 (本地文件提取，不需要 Hook)
    display_image_keys()

    # 2. 初始化数据库密钥 Hook
    console.print(f"\n[bold yellow][*] 正在向目标进程 {target_pid} 注入 Hook (数据库密钥)...[/bold yellow]")
    success = wx_key.initialize_hook(target_pid)

    # 打印后台初始化日志
    msg, level = wx_key.get_status_message()
    while msg is not None:
        console.print(f"[{'dim cyan' if level == 0 else 'bold green' if level == 1 else 'bold red'}][*] Backend:[/] {msg}")
        msg, level = wx_key.get_status_message()

    if not success:
        console.print(f"\n[bold red]❌ Hook 初始化失败: {wx_key.get_last_error_msg()}[/bold red]")
        return

    console.print("\n[bold green]✅ Hook 系统已启动并挂载！请在微信中执行登录或解锁操作。[/bold green]\n")

    try:
        with Live(Spinner("dots", text="等待触发 Hook... (按 Ctrl+C 退出)", style="magenta"),
                  refresh_per_second=10) as live:
            while True:
                # 实时显示后台日志
                msg, level = wx_key.get_status_message()
                while msg is not None:
                    live.stop()
                    console.print(f"[{'dim cyan' if level == 0 else 'bold green' if level == 1 else 'bold red'}][*] Backend:[/] {msg}")
                    live.start()
                    msg, level = wx_key.get_status_message()

                # 轮询数据库密钥
                result = wx_key.poll_key_data()
                if result and 'key' in result:
                    live.stop()
                    display_captured_key(result['key'])
                    console.print("\n[bold green]🎉 恭喜！数据库密钥已捕获完毕！[/bold green]")
                    break
                    
                time.sleep(0.1)

    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] 收到中断信号，准备退出...[/bold yellow]")
    finally:
        console.print("[*] 正在清理内存并还原目标进程的指令集...")
        wx_key.cleanup_hook()
        console.print("[bold green]✅ 资源释放完毕，Hook 已安全卸载。[/bold green]")

if __name__ == "__main__":
    main()
