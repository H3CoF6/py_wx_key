import wx_key
import time
import sys

# ================= 配置区域 =================
# 1. 在任务管理器找到 WeChat.exe 的 PID 填入此处
TARGET_PID = 4516  # <--- 请修改这里！！！

# 2. IDA 脚本生成的特征数据
IDA_PATTERN = "55 41 57 41 56 56 57 53 48 83 EC 58 48 8D 6C 24 00 48 C7 45 00 FE FF FF FF 44 89 CF 44 89 C3 49 89 D6"
IDA_MASK = "xxxxxxxxxxxxxxxx?xxxxxxxxxxxxxxxxx"
IDA_OFFSET = 12


# ===========================================

def main():
    print(f"[*] 正在尝试 Hook 进程 PID: {TARGET_PID}")
    print(f"[*] 特征码: {IDA_PATTERN[:20]}...")
    print(f"[*] 偏移量: {IDA_OFFSET}")

    # -----------------------------------------------------------
    # 1. 初始化 Hook (对应 C# InitializeHook)
    # -----------------------------------------------------------
    # 参数: pid, version(留空), pattern, mask, offset
    if not wx_key.initialize_hook(TARGET_PID, "", IDA_PATTERN, IDA_MASK, IDA_OFFSET):
        # 获取错误信息 (对应 C# GetLastErrorMsg)
        err = wx_key.get_last_error_msg()
        print(f"\n[!] 初始化失败: {err}")
        print("[!] 请检查 PID 是否正确，或尝试以【管理员身份】运行此脚本。")
        return

    print("[+] Hook 初始化成功！正在监听密钥输出 (按 Ctrl+C 停止)...")
    print("-" * 50)

    try:
        while True:
            # -----------------------------------------------------------
            # 2. 轮询密钥 (对应 C# PollKeyData)
            # -----------------------------------------------------------
            # 只要有 key 返回，就说明截获到了
            key = wx_key.poll_key_data()
            if key:
                print(f"\n[★ KEY FOUND] 成功获取密钥: {key}")
                print(f"[★] 你现在可以使用这个密钥去解密数据库了！\n")

            # -----------------------------------------------------------
            # 3. 轮询内部日志 (对应 C# GetStatusMessage)
            # -----------------------------------------------------------
            # 循环读取，直到把积压的日志读完
            while True:
                msg, level = wx_key.get_status_message()
                if msg is None:
                    break

                # 格式化日志等级 (0=Info, 1=Success, 2=Error)
                tag_map = {0: "INFO", 1: "SUCCESS", 2: "ERROR"}
                tag = tag_map.get(level, "LOG")

                # 只有 Error 和 Success 才高亮显示，普通 Info 太多了可能会刷屏
                if level == 2:
                    print(f"[{tag}] {msg}")
                else:
                    print(f"[{tag}] {msg}")

            # -----------------------------------------------------------
            # 4. 避免 CPU 跑满 (对应 C# await Task.Delay(100))
            # -----------------------------------------------------------
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[*] 用户手动停止...")

    finally:
        # -----------------------------------------------------------
        # 5. 清理资源 (对应 C# CleanupHook) - 非常重要！！
        # -----------------------------------------------------------
        print("[*] 正在卸载 Hook...")
        wx_key.cleanup_hook()
        print("[+] 资源已释放，程序退出。")


if __name__ == "__main__":
    main()