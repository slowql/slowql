"""
SQLGuard - SQL Query Analysis Tool
Compatibility shim for legacy installers. Primary metadata lives in pyproject.toml.
"""

from pathlib import Path
from setuptools import setup, find_packages

readme_path = Path("README.md")
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else "SQLGuard — cinematic SQL analyzer"

# Keep a small compatibility fallback for editable installs.
# Do NOT duplicate dependencies, extras, or entry_points here — pyproject.toml is authoritative.
setup(
    name="slowql",
    version="1.0.0",
    author="El Mehdi Makroumi",
    author_email="elmehdi.makroumi@gmail.com",
    description="SQL query analyzer for detecting anti-patterns and performance issues",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/makroumi/slowql",
    project_urls={
        "Bug Tracker": "https://github.com/makroumi/slowql/issues",
        "Documentation": "https://github.com/makroumi/slowql#readme",
        "Source Code": "https://github.com/makroumi/slowql",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Database",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    keywords="sql, query, optimization, performance, analysis, database",
    include_package_data=True,
    zip_safe=False,
)
