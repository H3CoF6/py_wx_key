from setuptools import setup, Distribution, find_packages

class BinaryDistribution(Distribution):
    def has_ext_modules(foo):
        return True

setup(
    name='wx_key',
    version='1.0.0',
    description='WeChat Key Hook',
    packages=find_packages(),
    package_data={
        'wx_key': ['*.pyd'],
    },
    distclass=BinaryDistribution,

    options={'bdist_wheel': {'plat_name': 'win_amd64'}},
)