# 🔥 SlowQL — Catch Expensive SQL Before Production

**Static SQL analyzer with a cyberpunk aesthetic.**  
Detects 50+ performance killers, security risks, and anti‑patterns before they cost you money.

---

## 🚀 Vision

SlowQL isn’t just another linter. It’s a **billion‑dollar safeguard** for data‑driven companies:  
- Prevent catastrophic table wipes before they hit prod.  
- Slash cloud bills by eliminating full‑table scans.  
- Harden pipelines against SQL injection and anti‑patterns.  
- Deliver **instant credibility** in CI/CD with cinematic, cyberpunk‑styled reports.  

---

## 🔗 Badges

### 📦 Package & Release
[![Release](https://img.shields.io/github/v/release/makroumi/slowql?logo=github&label=v1.0.3)](https://github.com/makroumi/slowql/releases)
[![PyPI](https://img.shields.io/pypi/v/slowql?logo=pypi)](https://pypi.org/project/slowql/)
[![License](https://img.shields.io/github/license/makroumi/slowql?logo=open-source-initiative)](LICENSE)
[![Docker](https://img.shields.io/docker/v/makroumi/slowql?logo=docker&label=docker)](https://hub.docker.com/r/makroumi/slowql)
[![GHCR](https://img.shields.io/badge/GHCR-slowql-blue?logo=github)](https://github.com/makroumi/slowql/pkgs/container/slowql)

### 📊 Downloads
[![Docker Pulls](https://img.shields.io/docker/pulls/makroumi/slowql?logo=docker&label=pulls)](https://hub.docker.com/r/makroumi/slowql)
[![PyPI Downloads](https://img.shields.io/badge/PyPI%20downloads-~1200%2Fmonth-blue?logo=pypi)](https://pypistats.org/packages/slowql)
[![GitHub stars](https://img.shields.io/github/stars/makroumi/slowql?style=social&logo=github)](https://github.com/makroumi/slowql/stargazers)

### 🧪 Tests & Quality
[![CI](https://github.com/makroumi/slowql/actions/workflows/ci.yml/badge.svg?logo=github)](https://github.com/makroumi/slowql/actions)
[![Coverage](https://codecov.io/gh/makroumi/slowql/branch/main/graph/badge.svg?logo=codecov)](https://codecov.io/gh/makroumi/slowql)
[![Ruff](https://img.shields.io/badge/linter-ruff-blue?logo=python)](https://github.com/charliermarsh/ruff)
[![Mypy](https://img.shields.io/badge/type_check-mypy-blue?logo=python)](http://mypy-lang.org/)
[![Tests](https://img.shields.io/badge/test_suite-pytest-blue?logo=pytest)](https://docs.pytest.org/)

### 🔒 Security & Dependencies
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-brightgreen?logo=dependabot)](https://github.com/makroumi/slowql/security/dependabot)
[![Security](https://img.shields.io/badge/security-scanned%20via%20Snyk-blue?logo=snyk)](https://snyk.io/test/github/makroumi/slowql)

### 📣 Community
[![Discussions](https://img.shields.io/github/discussions/makroumi/slowql?logo=github)](https://github.com/makroumi/slowql/discussions)
[![Contributors](https://img.shields.io/github/contributors/makroumi/slowql?logo=github)](https://github.com/makroumi/slowql/graphs/contributors)
[![Sponsor](https://img.shields.io/github/sponsors/makroumi?logo=github)](https://github.com/sponsors/makroumi)

---

![SlowQL Demo](assets/demo.gif)

---

## ⚡ Quick Start

```bash
pip install slowql
slowql --input-file your_queries.sql
```

Or analyze queries interactively:


```bash
slowql --mode paste
```

---

## 🎯 What It Catches

| Severity | Issue | Impact |
|----------|-------|--------|
| 🚨 **CRITICAL** | DELETE/UPDATE without WHERE | Prevents accidental table wipes |
| 🔥 **HIGH** | Non‑SARGable queries | Forces full table scans instead of index seeks |
| 🔥 **HIGH** | Leading wildcards (LIKE '%x') | Prevents index usage |
| 💫 **MEDIUM** | SELECT * usage | Unnecessary data transfer, prevents covering indexes |
| 💠 **LOW** | Unnecessary DISTINCT | Adds sorting overhead |

**50+ detectors total** covering performance, security, and maintainability.

---

## 📊 Example


```bash
slowql --input-file examples/nasty_queries.sql
```

```
╔═══════════════════════════════════════════════╗
║     SQL Analysis Results                      ║
╚═══════════════════════════════════════════════╝

Found 46 optimization opportunities
Across 21 different issue types

🚨 CRITICAL: 2
🔥 HIGH    : 8  
💫 MEDIUM  : 7
💠 LOW     : 4

🔴 CRITICAL: Missing WHERE in UPDATE/DELETE
   Query: DELETE FROM users
   Fix: Add WHERE clause or use TRUNCATE if intentional
   Impact: Can delete/update entire table accidentally
```

---

## 🚀 Features

- **Cyberpunk CLI** — cinematic terminal output with optional Matrix intro  
- **Multiple formats** — export to HTML, JSON, or CSV  
- **CI/CD ready** — `--fast --non-interactive` for pipelines  
- **Database‑free** — analyzes SQL strings statically  

---

## 📖 Usage

### Analyze a file

```bash
slowql --input-file queries.sql --export html
```

### Interactive mode

```bash
slowql
# Paste your SQL, press Ctrl+D when done
```

### CI/CD integration

```bash
slowql --input-file schema.sql --export json --fast --non-interactive
```

### Python API

```python
from slowql.core.analyzer import QueryAnalyzer

analyzer = QueryAnalyzer()
results = analyzer.analyze("SELECT * FROM users WHERE id = 1")
print(results)
```

---

## 🛠️ Installation

**Recommended (isolated):**

```bash
pipx install slowql
```

**Standard:**

```bash
pip install slowql
```

**From source:**

```bash
git clone https://github.com/makroumi/slowql
cd slowql
pip install -e .
```

---

## 🧪 Development

```bash
pip install -e '.[dev]'
pytest
pytest --cov=slowql
```

---

## 📝 License

Apache 2.0 — see [LICENSE](LICENSE)

---

## 🤝 Contributing

Issues and PRs welcome! Please run tests before submitting.  
For major changes, open a discussion first.

---

**Built by [@makroumi](https://github.com/makroumi)**  
📢 [Report Issues](https://github.com/makroumi/slowql/issues)
