# WeChat Key Hook Python Module (ABI3 / Limited API)

这是一个支持 **Python Limited API (abi3)** 的微信密钥获取模块。

## 什么是 abi3？
通常情况下，C++ 编写的 Python 扩展（.pyd）必须针对特定的 Python 版本（如 3.11）进行编译，且不能在其他版本（如 3.9 或 3.12）上运行。
**abi3** 解决了这个问题：
- **一次编译，到处运行**：在 Python 3.7 环境下编译生成的 `wx_key.abi3.pyd`，可以直接在 Python 3.8, 3.9, 3.10, 3.11, 3.12 等所有后续版本中运行。
- **方便分发**：您只需要分发这一个文件给其他 Python 开发者，他们无需安装 C++ 环境即可直接使用。

## 编译要求
1. **Windows 10/11**
2. **Visual Studio 2019/2022** (需勾选 "使用 C++ 的桌面开发")
3. **CMake 3.12+**
4. **Python 3.7+**
5. **Pybind11**: `pip install pybind11`

## 编译步骤
1. 安装依赖：
   ```bash
   pip install pybind11
   ```
2. 编译：
   ```bash
   mkdir build
   cd build
   cmake ..
   cmake --build . --config Release
   ```
3. 编译完成后，在 `Release` 目录下会生成 **`wx_key.abi3.pyd`**。

## 分发与使用
您可以直接将 `wx_key.abi3.pyd` 发送给其他开发者。他们只需要确保：
1. 使用的是 **Windows 64位** 系统（如果您是在 64 位下编译的）。
2. Python 版本 **>= 3.7**。

使用方法与普通模块完全一致：
```python
import wx_key
# ... 调用函数 ...
```

## 函数说明
- `initialize_hook(pid, version, pattern, mask, offset)`: 安装 Hook。
- `poll_key_data(buffer_size=65)`: 检查是否有新密钥。
- `get_status_message()`: 获取最新状态。返回 `(message, level)`。
- `cleanup_hook()`: 卸载 Hook。
- `get_last_error_msg()`: 获取错误描述。
