from setuptools import setup, find_packages
from os.path import join, dirname
import protocol

setup(
    name="skyx_protocol",
    version=protocol.__version__,
    packages=find_packages(),
    long_description=open(join(dirname(__file__), "README.md")).read(),
    install_requires=[
        "pycryptodome==3.10.4"
    ],
)
