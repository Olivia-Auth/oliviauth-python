"""
Olivia Auth Python SDK Setup

Install with: pip install .
Install with WebSocket support: pip install .[websocket]
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="oliviauth",
    version="1.0.0",
    author="Olivia Auth",
    author_email="support@oliviauth.com",
    description="Python SDK for Olivia Auth - Software Licensing Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Olivia-Auth/oliviauth-python",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "cryptography>=40.0.0",
    ],
    extras_require={
        "websocket": [
            "python-socketio[client]>=5.8.0",
            "websocket-client>=1.5.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
        ],
    },
    keywords="authentication, license, sdk, security, encryption, licensing",
    project_urls={
        "Bug Reports": "https://github.com/Olivia-Auth/oliviauth-python/issues",
        "Documentation": "https://github.com/Olivia-Auth/oliviauth-python#readme",
        "Source": "https://github.com/Olivia-Auth/oliviauth-python",
    },
)
