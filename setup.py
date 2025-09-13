#!/usr/bin/env python3
"""
Setup script for POPIA Privacy-as-Code Toolkit
"""

from setuptools import setup, find_packages
import os
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
def read_requirements(filename):
    """Read requirements from file"""
    with open(filename, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Version
VERSION = "1.0.0"

setup(
    name="popia-toolkit",
    version=VERSION,
    author="POPIA Toolkit Team",
    author_email="dev@popia-toolkit.com",
    description="A Privacy-as-Code toolkit for South African POPIA compliance",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/popia-toolkit",
    project_urls={
        "Bug Reports": "https://github.com/your-org/popia-toolkit/issues",
        "Source": "https://github.com/your-org/popia-toolkit",
        "Documentation": "https://popia-toolkit.readthedocs.io",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
    ],
    keywords="popia privacy pii compliance south-africa security data-protection gdpr",
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "regex>=2022.0.0",
        "spacy>=3.4.0",
        "presidio-analyzer>=2.2.0",
        "presidio-anonymizer>=2.2.0",
        "reportlab>=3.6.0",
        "boto3>=1.24.0",
        "azure-storage-blob>=12.0.0",
        "requests>=2.28.0",
        "jinja2>=3.0.0",
        "rich>=12.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
            "twine>=4.0.0",
            "wheel>=0.37.0",
        ],
        "cloud": [
            "boto3>=1.24.0",
            "azure-storage-blob>=12.0.0",
            "google-cloud-storage>=2.5.0",
        ],
        "web": [
            "fastapi>=0.85.0",
            "uvicorn[standard]>=0.18.0",
            "python-multipart>=0.0.5",
            "aiofiles>=0.8.0",
        ],
        "all": [
            "boto3>=1.24.0",
            "azure-storage-blob>=12.0.0",
            "google-cloud-storage>=2.5.0",
            "fastapi>=0.85.0",
            "uvicorn[standard]>=0.18.0",
            "python-multipart>=0.0.5",
            "aiofiles>=0.8.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "popia=popia_toolkit.cli:main",
            "popia-scan=popia_toolkit.scanner:main",
            "popia-validate=popia_toolkit.policy_engine:main",
            "popia-report=popia_toolkit.report_generator:main",
        ],
    },
    include_package_data=True,
    package_data={
        "popia_toolkit": [
            "templates/*.html",
            "templates/*.md",
            "policies/*.rego",
            "patterns/*.json",
            "static/*",
        ],
    },
    data_files=[
        ("share/popia-toolkit/examples", [
            "examples/sample_config.yaml",
            "examples/github_workflow.yml",
            "examples/test_data.py",
        ]),
        ("share/popia-toolkit/policies", [
            "policies/default.rego",
            "policies/custom_example.rego",
        ]),
    ],
    zip_safe=False,
    platforms=["any"],
    license="MIT",
    test_suite="tests",
    tests_require=[
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
        "pytest-mock>=3.10.0",
    ],
)