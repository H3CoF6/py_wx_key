#!/usr/bin/env python3
"""校验 bdist_wheel 产物里恰好有一个、且与目标解释器匹配的扩展模块。

这个打包方式是"预编译二进制 + setup.py"，package_data 用通配符收 *.pyd/*.so，
所以两类错误都不会让 bdist_wheel 失败：

- 漏 cp（空包）：产出一个没有扩展模块的坏 wheel；
- packaging/wx_key/ 里混进别的平台或别的 Python 版本的旧产物：每个 wheel
  都连带多打一份无用的二进制（Windows 的 wheel 里塞进 linux .so 这种）。

用法: python scripts/verify_wheel.py [glob]   # 默认 packaging/dist/*.whl

注意：运行期输出必须是纯 ASCII（脚本自身可以是 UTF-8）。CI 的 Windows runner
控制台编码是 cp1252，print 中文会 UnicodeEncodeError 把整个 job 弄挂。
"""

from __future__ import annotations

import glob
import sys
import zipfile

EXTENSIONS = (".so", ".pyd")


def _matches_target(name: str, major: int, minor: int) -> bool:
    """Windows 是 wx_key.cp311-win_amd64.pyd，Linux 是 wx_key.cpython-311-...so。"""
    return f"cp{major}{minor}" in name or f"cpython-{major}{minor}" in name


def main(argv: list[str]) -> int:
    pattern = argv[1] if len(argv) > 1 else "packaging/dist/*.whl"
    major, minor = sys.version_info[:2]
    wheels = sorted(glob.glob(pattern))
    if not wheels:
        print(f"FAIL: no wheel matched {pattern}")
        return 1

    failed = False
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            modules = [n for n in archive.namelist() if n.endswith(EXTENSIONS)]
        ok = len(modules) == 1 and _matches_target(modules[0], major, minor)
        print(
            f"{'OK  ' if ok else 'FAIL'} {wheel} "
            f"(target cp{major}{minor}) -> {modules}"
        )
        failed |= not ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
