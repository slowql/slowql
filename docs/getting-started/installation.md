# Installation

SlowQL can be installed in multiple ways depending on your environment and workflow. This page covers installation from **PyPI**, **Docker (GHCR)**, and **GitHub Releases**.

---

## 📦 Install from PyPI

The simplest way to install SlowQL is via pip:

```Bash
pip install slowql
```
This will install the latest stable release directly from [PyPI](https://pypi.org/project/slowql/).

---

## 🐳 Install via Docker (GHCR)

SlowQL is also available as a container image hosted on GitHub Container Registry (GHCR):

```Bash
docker pull ghcr.io/makroumi/slowql:latest
docker run --rm -it ghcr.io/makroumi/slowql --help
```
This method is ideal for isolated environments or CI/CD pipelines.

---

## 🧬 Install from GitHub Releases

You can download prebuilt binaries or source archives from the [GitHub Releases](https://github.com/makroumi/slowql/releases) page.

```Bash
wget https://github.com/makroumi/slowql/releases/download/v1.0.0/slowql-linux-amd64
chmod +x slowql-linux-amd64
./slowql-linux-amd64 --help
```

---

## ✅ Verify Installation


```Bash
slowql --version
```
You should see the current version number printed to the terminal.
