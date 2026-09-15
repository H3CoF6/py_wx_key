import sys

from setuptools import setup, Distribution, find_packages


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


setup(
    name='wx_key',
    version='2.0.1',
    description='WeChat Key Hook',
    packages=find_packages(),
    package_data={
        'wx_key': ['*.pyd', '*.so'],
    },
    distclass=BinaryDistribution,
    # Windows: 固定 win_amd64（CI 用 windows-latest 构建）。
    # Linux: 交给 bdist_wheel 用本机 tag（linux_x86_64），产物基线是构建机——
    # CI 固定用 ubuntu-22.04（glibc 2.35），比它更老的发行版跑不了，属预期。
    options={'bdist_wheel': {'plat_name': 'win_amd64'}} if sys.platform == 'win32' else {},
)