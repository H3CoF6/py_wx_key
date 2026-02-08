# py_wx_key   (Python Extension)

**py_wx_key** 是一个用于获取微信数据库密钥的 Python 原生扩展模块（.pyd）。它允许开发者在 Python 中直接读取微信数据库密钥，无需通过 DLL 注入或复杂的内存扫描工具。

> **致谢 / Acknowledgements**
>
> 本项目的核心逻辑（Shellcode 注入、Hook 机制、IPC 通信）**大量参考与复刻**自 [ycccccccy/wx_key](https://github.com/ycccccccy/wx_key)。
>
> 在此基础上，本项目进行了 Python 绑定移植，并重构了初始化逻辑以支持动态特征码。

------

## 1. 设计理念

与原版 `wx_key.dll` 不同，本项目认为特征码**应该由外部传入，而不是硬编码**。

- **原版逻辑**：DLL 内部维护了一份特征码列表，微信更新版本后，必须重新编译 DLL 才能支持。
- **本项目逻辑**：我们将特征码匹配逻辑剥离到上层。核心模块只负责“执行”，特征码（Pattern）、掩码（Mask）和偏移（Offset）由调用者（开发者）通过参数传入。
  - 这意味着当微信更新时，你通常**无需重新编译**本项目，只需运行配套的 IDA 脚本更新参数即可。

------

## 2. 编译与安装

由于本项目是一个 C++ 编写的 Python 扩展，你需要自行编译或使用 Wheel 包安装。

### 环境要求

- Windows 10/11 x64
- Python 3.10+ (建议)
- Visual Studio 2022 (安装 C++ 开发组件)
- CMake 3.12+

### 手动编译 (推荐)

我们推荐使用 `pip` 或 `setup.py` 进行构建，这将自动处理 `pybind11` 依赖和编译配置。

```powershell
# 1. 克隆仓库
git clone https://github.com/your-repo/wx_key.git
cd wx_key

# 2. 方式 A: 直接编译并安装到当前 Python 环境
pip install .

# 3. 方式 B: 打包为 Wheel 文件 (方便分发)
pip install wheel
python setup.py bdist_wheel
# 生成的 .whl 文件位于 dist/ 目录下
```

> **注意**：本项目不支持 Python ABI3（稳定 ABI），因此你需要为你使用的特定 Python 版本（如 cp310, cp311）分别编译对应的 Wheel 包。

------

## 3. IDA 脚本使用说明 (关键)

为了获取初始化所需的参数，本项目提供了一个强大的 IDA 脚本。

### 使用步骤：

1. 使用 **IDA Pro** (64位) 打开目标版本的 `WeChatWin.dll`。
2. 等待 IDA 分析完成（左下角显示 idle）。
3. 点击菜单 `File` -> `Script file...`，选择 `scripts/ida_pattern_gen.py` 并运行。
4. 脚本会自动在控制台输出如下关键信息：

```plaintext
==================== 复制以下内容到 Python ====================
pattern = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 41 8B F9"
mask    = "xxxx?xxxx?xxxx?xxx?xxx"
offset  = 123  (0x7B)
------------------------------------------------------------
```

请记录下这三个值，它们是调用 `initialize_hook` 的必要参数。

------

## 4. API 接口说明

模块名：`wx_key`

### `initialize_hook`

**功能**：初始化 Hook 系统，注入 Shellcode。

```python
def initialize_hook(
    target_pid: int, 
    version: str = "", 
    pattern: str, 
    mask: str, 
    offset: int
) -> bool
```

- `target_pid`: 目标微信进程 ID。
- `version`: (可选) 校验用的版本号字符串，留空则不校验。
- `pattern`: **(关键)** 从 IDA 脚本获取的 Hex 特征码字符串。
- `mask`: **(关键)** 从 IDA 脚本获取的掩码字符串。
- `offset`: **(关键)** 从 IDA 脚本获取的十进制偏移量。

### `poll_key_data`

**功能**：非阻塞轮询密钥。

```python
def poll_key_data(buffer_size: int = 65) -> str | None
```

- 返回：成功则返回 64 位 HEX 密钥字符串，无数据则返回 `None`。

### `get_status_message`

**功能**：获取底层 C++ 模块的运行日志。

```python
def get_status_message() -> tuple[str, int] | tuple[None, -1]
```

- 返回：`(日志内容, 等级)`。等级：0=Info, 1=Success, 2=Error。

### `cleanup_hook`

**功能**：清理资源，卸载 Hook。**程序退出前必须调用**。

------

## 5. Python 调用示例

```python
import time
import wx_key
import psutil

# 1. 获取微信 PID
def get_wechat_pid():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'WeChat.exe':
            return proc.info['pid']
    return None

def main():
    pid = get_wechat_pid()
    if not pid:
        print("未找到微信进程")
        return

    # ---------------------------------------------------------
    # 2. 配置特征码 (数据来源：运行 scripts/ida_pattern_gen.py)
    # ---------------------------------------------------------
    # 示例数据，请务必使用脚本针对你的微信版本生成真实数据！！！
    PATTERN = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 41 8B F9"
    MASK    = "xxxx?xxxx?xxxx?xxx?xxx"
    OFFSET  = 123 

    print(f"正在 Hook 进程 {pid} ...")
    
    # 3. 初始化
    if not wx_key.initialize_hook(pid, "", PATTERN, MASK, OFFSET):
        print("初始化失败！请检查特征码或权限。")
        # 获取错误详情
        err_msg = wx_key.get_last_error_msg()
        print(f"错误信息: {err_msg}")
        return

    print("Hook 成功，正在监听密钥...")

    try:
        while True:
            # 4. 轮询密钥
            key = wx_key.poll_key_data()
            if key:
                print(f"\n[★] 捕获到密钥: {key}")
                print("可以将密钥保存或用于解密数据库...")
            
            # 5. 读取底层日志 (可选)
            msg, level = wx_key.get_status_message()
            if msg:
                tags = ["[INFO]", "[SUCCESS]", "[ERROR]"]
                tag = tags[level] if 0 <= level < 3 else "[LOG]"
                print(f"{tag} {msg}")

            time.sleep(0.1) # 防止 CPU 占用过高

    except KeyboardInterrupt:
        print("\n停止监听...")
    finally:
        # 6. 清理资源 (非常重要！！！)
        wx_key.cleanup_hook()
        print("资源已释放")

if __name__ == "__main__":
    main()
```

------

## 6. 常见问题

1. **`ImportError: DLL load failed`**:
   - 确保已安装 VC++ 运行库。
   - 确保你的 Python 版本与编译该 `.pyd` 时的 Python 版本一致。
2. **`InitializeHook` 返回 False**:
   - 请使用管理员权限运行 Python。
   - 请确保 **pattern/mask/offset** 与当前运行的微信版本完全匹配（使用 IDA 脚本重新生成）。
3. **如何适配新版微信？**:
   - 不需要修改 C++ 源码。
   - 只需用 IDA 打开新版 `WeChatWin.dll`，运行脚本，将输出的新参数填入 Python 代码即可。

------

## 免责声明

本项目仅供计算机安全研究与学习使用。请勿用于任何非法用途。用户在使用本项目时产生的一切后果由用户自行承担。
