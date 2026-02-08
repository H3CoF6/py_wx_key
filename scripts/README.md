ida运行该脚本，可以**自动化获取**hook函数的信息

```text
==================== 复制以下内容到 Python/C++ ====================
pattern = "55 41 57 41 56 56 57 53 48 83 EC 58 48 8D 6C 24 ? 48 C7 45 00 FE FF FF FF 44 89 CF 44 89 C3 49 89 D6"
mask    = "xxxxxxxxxxxxxxxx?xxxxxxxxxxxxxxxxx"
offset  = 12  (0xC)
------------------------------------------------------------
[Debug info]
Function Start : 0x1805325c0
Hook Address   : 0x1805325cc
============================================================
```

