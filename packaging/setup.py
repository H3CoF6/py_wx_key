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
    # Windows: 固定 win_amd64；Linux: 让 bdist_wheel 用本机 tag（manylinux 由
    # auditwheel 在 CI 里重打）
    options={'bdist_wheel': {'plat_name': 'win_amd64'}} if sys.platform == 'win32' else {},
)