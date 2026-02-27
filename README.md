# py_wx_key   (Python Extension)

**py_wx_key** 是一个用于获取微信核心密钥的 Python 原生扩展模块（.pyd）。它允许开发者在 Python 中直接读取**微信数据库密钥 (DB Key)** 以及**图片解密密钥 (Image Key)**，无需通过 DLL 注入或复杂的内存扫描工具。

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
git clone [https://github.com/your-repo/wx_key.git](https://github.com/your-repo/wx_key.git)
cd wx_key

# 2. 方式 A: 直接编译并安装到当前 Python 环境
pip install .

# 3. 方式 B: 打包为 Wheel 文件 (方便分发)
pip install wheel
python setup.py bdist_wheel
# 生成的 .whl 文件位于 dist/ 目录下

```

> **注意**：本项目不支持 Python ABI3（稳定 ABI），因此你需要为你使用的特定 Python 版本（如 cp310, cp311）分别编译对应的 Wheel 包。

---

## 3. IDA 脚本使用说明 (关键)

为了获取初始化所需的参数，本项目提供了一个强大的 IDA 脚本以提取双重特征码（DB Key 与 Image Key）。

### 使用步骤：

1. 使用 **IDA Pro** (64位) 打开目标版本的 `WeChatWin.dll`。
2. 等待 IDA 分析完成（左下角显示 idle）。
3. 点击菜单 `File` -> `Script file...`，选择配套的 `ida_pattern_gen.py` 并运行。
4. 脚本会自动在控制台输出如下关键信息：

```plaintext
==================== 复制以下内容到 Python ====================
[DB Key 提取参数]
pattern = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 41 8B F9"
mask    = "xxxx?xxxx?xxxx?xxx?xxx"
offset  = 123  (0x7B)

[Image Key 提取参数]
md5_pattern = "48 8D 4D 00 48 89 4D B0 48 89 45 B8 48 8D 7D 00 48 8D 55 B0 48 89 F9"
md5_mask    = "xxx?xxxxxxxxxxx?xxxxxxx"
md5_offset  = 4
------------------------------------------------------------

```

请记录下这些值，它们是调用 `initialize_hook` 的必要参数。

---

## 4. API 接口说明

模块名：`wx_key`

### `initialize_hook`

**功能**：初始化 Hook 系统，注入双路 Shellcode。

```python
def initialize_hook(
    target_pid: int, 
    version: str = "", 
    key_pattern: str, 
    key_mask: str, 
    key_offset: int,
    md5_pattern: str,
    md5_mask: str,
    md5_offset: int
) -> bool

```

* `target_pid`: 目标微信进程 ID。
* `version`: (可选) 校验用的版本号字符串，留空则不校验。
* `key_*`: **(关键)** 数据库密钥的特征码参数。
* `md5_*`: **(关键)** 图片解密密钥 (MD5) 的特征码参数。

### `poll_key_data`

**功能**：非阻塞轮询捕获到的密钥数据。

```python
def poll_key_data() -> dict | None

```

* 返回：成功则返回一个字典，可能包含以下键值，无数据则返回 `None`。
* `'key'`: 64 位 HEX 数据库密钥 (DB Key)。
* `'md5'`: 32 位 图片解密密钥 (Image Key，本质是特定字符串的 MD5 哈希)。



### `get_status_message`

**功能**：获取底层 C++ 模块的运行日志。

```python
def get_status_message() -> tuple[str, int] | tuple[None, -1]

```

* 返回：`(日志内容, 等级)`。等级：0=Info, 1=Success, 2=Error。

### `cleanup_hook`

**功能**：清理内存资源，卸载 Hook。**程序退出前必须调用**，否则可能导致目标进程崩溃。

---

## 5. Python 调用示例

```python
import time
import wx_key
import psutil

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

    # 此处省略具体特征码，请使用 IDA 脚本生成
    KEY_PATTERN, KEY_MASK, KEY_OFFSET = "...", "...", 0
    MD5_PATTERN, MD5_MASK, MD5_OFFSET = "...", "...", 0

    print(f"正在 Hook 进程 {pid} ...")
    
    # 初始化
    if not wx_key.initialize_hook(pid, "", KEY_PATTERN, KEY_MASK, KEY_OFFSET, MD5_PATTERN, MD5_MASK, MD5_OFFSET):
        print(f"初始化失败！错误信息: {wx_key.get_last_error_msg()}")
        return

    print("Hook 成功，请在微信中执行登录或解锁操作...")

    captured_key = False
    captured_md5 = False

    try:
        while True:
            result = wx_key.poll_key_data()
            if result:
                if 'key' in result:
                    print(f"\n[★] 捕获 DB 密钥: {result['key']}")
                    captured_key = True
                if 'md5' in result:
                    print(f"\n[★] 捕获图片密钥: {result['md5']}")
                    captured_md5 = True

                # 双数据都拿到后安全退出
                if captured_key and captured_md5:
                    break

            time.sleep(0.05)
    except KeyboardInterrupt:
        pass
    finally:
        # 卸载 Hook 并恢复目标进程指令
        wx_key.cleanup_hook()
        print("资源已释放，安全退出。")

if __name__ == "__main__":
    main()

```

---

## 6. 常见问题

1. **`ImportError: DLL load failed`**:
* 确保已安装 VC++ 运行库。
* 确保你的 Python 版本与编译该 `.pyd` 时的 Python 版本一致。


2. **`InitializeHook` 返回 False**:
* 请使用管理员权限运行 Python。
* 请确保 **pattern/mask/offset** 与当前运行的微信版本完全匹配（使用 IDA 脚本重新生成）。


3. **如何适配新版微信？**:
* 不需要修改 C++ 源码。
* 只需用 IDA 打开新版 `WeChatWin.dll`，运行脚本，将输出的新特征码参数填入 Python 代码即可。



---

## 免责声明

本项目仅供计算机安全研究与学习使用。请勿用于任何非法用途。用户在使用本项目时产生的一切后果由用户自行承担。
