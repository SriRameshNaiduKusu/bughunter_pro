#!/usr/bin/env python3
"""
BugHunter Pro - Setup Script (backward compatibility)
Install with: pip install . OR pip install -e .
"""

import sys
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop


class PostInstallCommand(install):
    """Post-installation: download SecLists."""
    def run(self):
        install.run(self)
        self._post_install()

    @staticmethod
    def _post_install():
        try:
            from bughunter_pro.installer import download_seclists
            download_seclists()
        except Exception as e:
            print(f"[!] Post-install SecLists download failed: {e}")
            print("[*] Run 'bughunter-install' manually to download SecLists.")


class PostDevelopCommand(develop):
    """Post-develop-installation: download SecLists."""
    def run(self):
        develop.run(self)
        self._post_install()

    @staticmethod
    def _post_install():
        try:
            from bughunter_pro.installer import download_seclists
            download_seclists()
        except Exception as e:
            print(f"[!] Post-install SecLists download failed: {e}")
            print("[*] Run 'bughunter-install' manually to download SecLists.")


setup(
    name="bughunter-pro",
    version="1.0.0",
    description="Comprehensive security reconnaissance and vulnerability scanner",
    long_description=open("README.md", encoding="utf-8").read()
    if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Cyber Security Student",
    author_email="student@herts.ac.uk",
    url="https://github.com/yourusername/bughunter-pro",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "requests[socks]>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.4.0",
        "python-whois>=0.9.4",
        "shodan>=1.31.0",
        "urllib3>=2.0.0",
        "colorama>=0.4.6",
        "jinja2>=3.1.0",
        "tldextract>=5.1.0",
        "PySocks>=1.7.1",
        "stem>=1.8.0",
        "GitPython>=3.1.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov>=4.0", "flake8>=6.0", "black>=23.0"],
    },
    entry_points={
        "console_scripts": [
            "bughunter=bughunter_pro.main:main",
            "bughunter-install=bughunter_pro.installer:main",
        ],
    },
    cmdclass={
        "install": PostInstallCommand,
        "develop": PostDevelopCommand,
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)