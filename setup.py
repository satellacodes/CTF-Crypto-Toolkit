#!/usr/bin/env python3
"""
Setup script for CTF Crypto Toolkit.
"""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ctf-crypto-toolkit",
    version="2.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced cryptographic tool for CTF challenges",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/CTF-Crypto-Toolkit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: Education",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.20.0",
        "argparse>=1.4.0",
        "requests>=2.31.0",
        "colorama>=0.4.6",
        "tqdm>=4.66.1",
        "cryptography>=41.0.7",
    ],
    entry_points={
        "console_scripts": [
            "ctf-crypto-tool=ctf_crypto_tool:main",
        ],
    },
    include_package_data=True,
    package_data={
        "wordlists": ["*.txt"],
        "examples": ["*.txt"],
    },
)
