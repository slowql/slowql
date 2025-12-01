# 🔥 SlowQL - Catch Expensive SQL Before Production

**Static SQL analyzer with a cyberpunk aesthetic.** Detects 50+ performance killers, security risks, and anti-patterns before they cost you money.

---

## 🔗 Badges 

<!-- Replace the placeholders below with actual badge URLs -->

[![PyPI](https://img.shields.io/pypi/v/slowql.svg)](https://pypi.org/project/slowql/)
[![Docker](https://img.shields.io/docker/pulls/makroumi/slowql.svg)](https://hub.docker.com/r/makroumi/slowql)
[![Coverage](https://codecov.io/gh/makroumi/slowql/branch/main/graph/badge.svg)](https://codecov.io/gh/makroumi/slowql)
[![License](https://img.shields.io/github/license/makroumi/slowql.svg)](https://github.com/makroumi/slowql/blob/main/LICENSE)
[![Ruff](https://img.shields.io/badge/linter-ruff-blue)](https://github.com/charliermarsh/ruff)
[![Mypy](https://img.shields.io/badge/type_check-mypy-blue)](http://mypy-lang.org/)
[![Tests](https://img.shields.io/badge/test_suite-pytest-blue)](https://docs.pytest.org/)
[![Discussions](https://img.shields.io/github/discussions/makroumi/slowql)](https://github.com/makroumi/slowql/discussions)
[![Sponsor](https://img.shields.io/github/sponsors/makroumi)](https://github.com/sponsors/makroumi)



[![Dependabot Status](https://img.shields.io/badge/dependabot-enabled-brightgreen)](https://github.com/makroumi/slowql/security/dependabot)
[![Vulnerabilities](https://img.shields.io/snyk/vulnerabilities/github/makroumi/slowql?label=vulnerabilities)](#)
[![Docs](https://img.shields.io/readthedocs/slowql?logo=read-the-docs)](https://your-docs-url)
[![Release](https://img.shields.io/github/v/release/makroumi/slowql?label=release)](https://github.com/makroumi/slowql/releases)

[![GitHub stars](https://img.shields.io/github/stars/makroumi/slowql?style=social)](https://github.com/makroumi/slowql/stargazers)
[![Contributors](https://img.shields.io/github/contributors/makroumi/slowql)](https://github.com/makroumi/slowql/graphs/contributors)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-FE7D7D)](https://github.com/sponsors/makroumi)

[![Discussions](https://img.shields.io/badge/discussions-on%20GitHub-586069?logo=github)](https://github.com/makroumi/slowql/discussions)



## ⚡ Quick Start
```bash
pip install slowql
slowql --input-file your_queries.sql
```

Or analyze queries interactively:
```bash
slowql --mode paste
```

## 🎯 What It Catches

| Severity | Issue | Impact |
|----------|-------|--------|
| 🚨 **CRITICAL** | DELETE/UPDATE without WHERE | Prevents accidental table wipes |
| 🔥 **HIGH** | Non-SARGable queries | Forces full table scans instead of index seeks |
| 🔥 **HIGH** | Leading wildcards (LIKE '%x') | Prevents index usage |
| 💫 **MEDIUM** | SELECT * usage | Unnecessary data transfer, prevents covering indexes |
| 💠 **LOW** | Unnecessary DISTINCT | Adds sorting overhead |

**50+ detectors total** covering performance, security, and maintainability.

## 📊 Example
```bash
$ slowql --input-file examples/nasty_queries.sql

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

## 🚀 Features

- **Beautiful CLI** - Cyberpunk-themed terminal output with optional Matrix intro
- **Multiple formats** - Export to HTML, JSON, or CSV
- **CI/CD ready** - Use `--fast --non-interactive` for pipelines
- **Zero dependencies** on your database - analyzes SQL strings statically

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

## 🧪 Development
```bash
# Install dev dependencies
pip install -e '.[dev]'

# Run tests
pytest

# Run with coverage
pytest --cov=slowql
```

## 📝 License

Apache 2.0 - see [LICENSE](LICENSE)

## 🤝 Contributing

Issues and PRs welcome! Please run tests before submitting.

---

**Built by [@makroumi](https://github.com/makroumi)** | **[Report Issues](https://github.com/makroumi/slowql/issues)**