# py_wx_key (Python Extension - Hybrid Mode)

**py_wx_key** 是一个用于获取微信核心密钥的 Python 原生扩展模块（.pyd）。它支持**自动扫描数据库密钥**、**手动/自动获取图片密钥**。

------

## 1. 核心功能

1.  **数据库密钥 (DB Key)**：完全自动。通过 `initialize_hook(pid)` 即可自动识别版本并完成 Hook，不再需要外部特征码。
2.  **图片密钥 (Image Key - 本地计算)**：新增 `get_image_key()` 接口。通过本地文件算法直接提取所有账号的解密参数（AES Key 和 XOR Key），**无需注入，无需 Hook，推荐使用**。
3.  **图片密钥 (Image Key - 内存 Hook)**：保留原有 Hook 接口。如果需要实时监控图片密钥生成，可以通过 `initialize_hook(pid, pattern, mask, offset)` 传入特征码进行 Hook。

------

## 2. API 接口说明

模块名：`wx_key`

### `initialize_hook`

**功能**：安装内存 Hook。数据库密钥 (DB Key) 始终会自动 Hook。

```python
# 方式 A: 只 Hook 数据库密钥 (全自动)
wx_key.initialize_hook(pid)

# 方式 B: 同时 Hook 数据库密钥 (自动) 和 图片密钥 (手动传入特征码)
wx_key.initialize_hook(pid, md5_pattern, md5_mask, md5_offset)
```

### `get_image_key`

**功能**：**本地提取**。通过扫描本地配置文件（MMKV/statistic）自动计算所有账号对应的图片加密参数。

```python
# 返回 JSON 字符串，包含所有账号的 aesKey 和 xorKey
json_str = wx_key.get_image_key()
```

### `poll_key_data`

**功能**：轮询捕获到的 Hook 数据。

```python
# 返回字典 {'key': '...', 'md5': '...'}
# 'key' 是数据库密钥，'md5' 是 Hook 模式捕获的图片解密参数
result = wx_key.poll_key_data()
```

### `cleanup_hook`

**功能**：卸载 Hook，释放资源。

---

## 3. 快速测试 (Demo)

我们提供了一个综合测试脚本 `scripts/test_all.py`，它演示了三种不同的获取方式：

```bash
# 1. 编译并安装
pip install .

# 2. 运行测试脚本 (需要管理员权限)
python scripts/test_all.py
```

---

## 免责声明

本项目仅供计算机安全研究与学习使用。请勿用于任何非法用途。用户在使用本项目时产生的一切后果由用户自行承担。
