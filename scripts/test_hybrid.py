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

# ================= 配置区域 =================
# 图片密钥 (Hook 模式) 仍然需要手动传入特征码
MD5_PATTERN = "48 8D 4D 00 48 89 4D B0 48 89 45 B8 48 8D 7D 00 48 8D 55 B0 48 89 F9"
MD5_MASK = "xxx?xxxxxxxxxxx?xxxxxxx"
MD5_OFFSET = 4
# ===========================================

def get_wechat_pid():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == 'weixin.exe':
            return proc.info['pid']
    return None

def print_header(pid):
    title = Text("WeChat Hybrid Key Capture System", justify="center", style="bold magenta")
    table = Table(show_header=False, expand=True, border_style="cyan")
    table.add_column("Function", style="bold cyan", width=25)
    table.add_column("Strategy", style="green")
    table.add_row("DB Key Capture", "Auto-Scanning Hook (No Pattern)")
    table.add_row("Image Key Capture (Hook)", "Manual Pattern Hook (Legacy)")
    table.add_row("Image Key Capture (Local)", "Local File Calc (New)")
    console.print(Panel(table, title=title, border_style="blue", padding=(1, 2)))

def run_local_extraction():
    """演示函数 1: 本地提取计算图片密钥"""
    console.print("\n[bold yellow][1] 正在执行本地文件算法提取 (无需 Hook)...[/bold yellow]")
    img_key_json = wx_key.get_image_key()
    if img_key_json:
        data = json.loads(img_key_json)
        table = Table(show_header=True, header_style="bold magenta", border_style="yellow")
        table.add_column("wxid", style="cyan")
        table.add_column("XOR Key", style="yellow")
        table.add_column("AES Key (16-char)", style="green")
        
        for account in data.get('accounts', []):
            wxid = account.get('wxid', 'unknown')
            for k in account.get('keys', []):
                table.add_row(wxid, str(k.get('xorKey')), k.get('aesKey'))
        console.print(table)
    else:
        console.print("[red]❌ 未能在本地找到有效的图片密钥信息。[/red]")

def run_dual_hook(pid):
    """演示函数 2 & 3: 初始化双 Hook 并轮询数据"""
    console.print(f"\n[bold yellow][2] 正在初始化双路 Hook (PID: {pid})...[/bold yellow]")
    console.print("[dim italic]注: 数据库密钥自动识别，图片密钥使用手动特征码。[/dim italic]")
    
    # 调用 initialize_hook (只传 MD5 参数，DB 自动完成)
    success = wx_key.initialize_hook(pid, MD5_PATTERN, MD5_MASK, MD5_OFFSET)
    
    # 打印后台初始化日志
    msg, level = wx_key.get_status_message()
    while msg:
        console.print(f"[*] Backend: {msg}")
        msg, level = wx_key.get_status_message()

    if not success:
        console.print(f"[bold red]❌ Hook 初始化失败: {wx_key.get_last_error_msg()}[/bold red]")
        return

    console.print("\n[bold green]✅ Hook 系统已启动！请在微信中执行登录或解锁操作。[/bold green]\n")

    captured_db = False
    captured_img = False

    try:
        with Live(Spinner("dots", text="等待触发 Hook... (按 Ctrl+C 退出)", style="magenta"),
                  refresh_per_second=10) as live:
            while True:
                # 显示后台状态
                msg, level = wx_key.get_status_message()
                while msg:
                    live.stop()
                    console.print(f"[*] Backend: {msg}")
                    live.start()
                    msg, level = wx_key.get_status_message()

                # 轮询捕获数据
                result = wx_key.poll_key_data()
                if result:
                    live.stop()
                    if 'key' in result:
                        console.print(Panel(f"[green bold]{result['key']}[/]", title="🔑 捕获: DB Key", border_style="green"))
                        captured_db = True
                    if 'md5' in result:
                        md5_16, xor_key = result['md5'].split('|')
                        console.print(Panel(f"MD5: {md5_16}\nXOR: {xor_key}", title="📦 捕获: Image Hook Data", border_style="yellow"))
                        captured_img = True
                    
                    if captured_db and captured_img:
                        console.print("\n[bold green]🎉 恭喜！所有 Hook 数据已收集完毕！[/bold green]")
                        break
                    live.start()
                
                time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        wx_key.cleanup_hook()
        console.print("[bold green]✅ Hook 已卸载，资源安全释放。[/bold green]")

def main():
    pid = get_wechat_pid()
    if not pid:
        console.print("[bold red]❌ 未找到运行中的 WeXin.exe 进程。[/bold red]")
        return

    print_header(pid)
    
    # 演示 1: 本地提取
    run_local_extraction()
    
    # 演示 2 & 3: 内存 Hook
    run_dual_hook(pid)

if __name__ == "__main__":
    main()
