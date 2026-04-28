import os
import sys
import ctypes
import platform
import psutil
import json

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def get_process_info(name_list):
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in [n.lower() for n in name_list]:
                procs.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs

def check_dll_arch(dll_path):
    # 简单的二进制检查 PE 头
    try:
        with open(dll_path, 'rb') as f:
            data = f.read(1024)
            pe_offset = data.find(b'PE\x00\x00')
            if pe_offset != -1:
                machine = data[pe_offset+4 : pe_offset+6]
                if machine == b'\x4c\x86': return "x64"
                if machine == b'\x4c\x01': return "x86"
    except:
        pass
    return "Unknown"

def run_diagnose():
    print("="*60)
    print(" WeChat DB Hook 环境诊断工具 ")
    print("="*60)

    # 1. 系统基本信息
    print(f"[*] 操作系统: {platform.platform()}")
    print(f"[*] Python 版本: {sys.version} ({platform.architecture()[0]})")
    print(f"[*] 管理员权限: {'[OK] 是' if is_admin() else '[!!] 否 (建议以管理员身份运行)'}")

    # 2. 查找微信进程
    print("\n[阶段 1: 进程检查]")
    targets = ['WeChat.exe', 'weixin.exe']
    procs = get_process_info(targets)
    if not procs:
        print("[!] 未找到运行中的微信进程 (WeChat.exe 或 weixin.exe)")
    else:
        for p in procs:
            print(f"[OK] 找到进程: {p['name']} | PID: {p['pid']} | 用户: {p['username']}")

    # 3. DLL 检查
    print("\n[阶段 2: 模块加载检查]")
    # 尝试寻找编译好的 pyd
    found_dll = None
    for root, dirs, files in os.walk('.'):
        for f in files:
            if f.startswith('wx_key') and (f.endswith('.pyd') or f.endswith('.dll')):
                found_dll = os.path.join(root, f)
                break
        if found_dll: break

    if not found_dll:
        print("[!] 错误: 未能在当前目录或子目录找到 wx_key 模块。请确保已编译项目。")
    else:
        arch = check_dll_arch(found_dll)
        print(f"[OK] 找到模块: {found_dll} ({arch})")
        if arch != "x64":
            print("[!] 警告: 该项目目前主要支持 x64，请确保编译目标正确。")

        try:
            # 模拟用户导入
            sys.path.append(os.path.dirname(found_dll))
            import wx_key
            print("[OK] 成功导入 wx_key 模块")
            
            # 4. 尝试初始化 Hook
            if procs:
                target_pid = procs[0]['pid']
                print(f"\n[阶段 3: 模拟调用 InitializeHook(PID={target_pid})...]")
                success = wx_key.initialize_hook(target_pid)
                
                if success:
                    print("[OK] 初始化成功！环境正常。")
                    wx_key.cleanup_hook()
                else:
                    error_msg = wx_key.get_last_error_msg()
                    print(f"[X] 初始化失败！")
                    print(f"    错误信息: {error_msg}")
                    
                    if "0xC000000B" in error_msg or "0xC0000005" in error_msg:
                        print("\n[分析结果] 检测到系统调用失败 (STATUS_INVALID_CID / ACCESS_DENIED)")
                        print("可能原因:")
                        print("1. 目标进程权限受限 (尝试关闭微信后重新以普通用户启动微信，或本工具以管理员运行)")
                        print("2. 杀毒软件/EDR 拦截了间接系统调用 (Indirect Syscalls)")
                        print("3. 微信主进程已退出或正在崩溃")
            else:
                print("\n[!] 跳过 Hook 测试，因为没找到微信进程。")

        except Exception as e:
            print(f"[X] 加载或调用模块时出错: {e}")

    print("\n" + "="*60)
    print(" 诊断完成，请将以上信息截图或复制给开发人员 ")
    print("="*60)
    input("\n按回车键退出...")

if __name__ == "__main__":
    run_diagnose()
