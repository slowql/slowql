# SlowQL

**Production-grade SQL static analyzer that prevents performance disasters, security breaches, and cloud cost explosions.**

Stop bad SQL before it hits production. SlowQL is a zero-dependency, offline SQL analyzer that catches performance anti-patterns, security vulnerabilities, compliance violations, and cost traps - with a beautiful terminal experience that developers actually enjoy using.

<!-- Package & Distribution -->
<p align="center">
  <a href="https://github.com/makroumi/slowql/releases"><img src="https://img.shields.io/github/v/release/makroumi/slowql?logo=github&label=release&color=4c1" alt="Release"></a>
  <a href="https://pypi.org/project/slowql/"><img src="https://img.shields.io/pypi/v/slowql?logo=pypi&logoColor=white&label=PyPI&color=3775A9" alt="PyPI"></a>
  <a href="https://pypi.org/project/slowql/"><img src="https://img.shields.io/pypi/pyversions/slowql?logo=python&logoColor=white&label=Python" alt="Python"></a>
  <a href="https://hub.docker.com/r/makroumi/slowql"><img src="https://img.shields.io/docker/v/makroumi/slowql?logo=docker&logoColor=white&label=Docker&color=2496ED" alt="Docker"></a>
  <a href="https://github.com/makroumi/slowql/pkgs/container/slowql"><img src="https://img.shields.io/badge/GHCR-available-181717?logo=github&logoColor=white" alt="GHCR"></a>
</p>

<p align="center">
  <a href="https://hub.docker.com/r/makroumi/slowql"><img src="https://img.shields.io/docker/pulls/makroumi/slowql?logo=docker&logoColor=white&label=Docker%20pulls" alt="Docker Pulls"></a>
  <a href="https://pypistats.org/packages/slowql"><img src="https://img.shields.io/pypi/dm/slowql?logo=pypi&logoColor=white&label=PyPI%20downloads" alt="PyPI Downloads"></a>
</p>

<!-- CI/CD & Quality -->
<p align="center">
  <a href="https://github.com/makroumi/slowql/actions/workflows/ci.yml"><img src="https://github.com/makroumi/slowql/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/makroumi/slowql"><img src="https://codecov.io/gh/makroumi/slowql/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/lint-ruff-46a758?logo=ruff&logoColor=white" alt="Ruff"></a>
  <a href="http://mypy-lang.org/"><img src="https://img.shields.io/badge/types-mypy-blue?logo=python&logoColor=white" alt="Mypy"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/makroumi/slowql?label=License&color=4c1" alt="License"></a>
</p>

<!-- Community -->
<p align="center">
  <a href="https://github.com/makroumi/slowql/stargazers"><img src="https://img.shields.io/github/stars/makroumi/slowql?style=social" alt="Stars"></a>
  <a href="https://github.com/makroumi/slowql/issues"><img src="https://img.shields.io/github/issues/makroumi/slowql?logo=github" alt="Issues"></a>
  <a href="https://github.com/makroumi/slowql/discussions"><img src="https://img.shields.io/github/discussions/makroumi/slowql?logo=github" alt="Discussions"></a>
  <a href="https://github.com/makroumi/slowql/graphs/contributors"><img src="https://img.shields.io/github/contributors/makroumi/slowql?logo=github&color=success" alt="Contributors"></a>
  <a href="https://github.com/sponsors/makroumi"><img src="https://img.shields.io/github/sponsors/makroumi?logo=github&color=ff69b4" alt="Sponsor"></a>
</p>

---

## 🎯 Why SlowQL?

**Real problems SlowQL prevents:**

| Problem | Impact | SlowQL Detection |
|---------|--------|------------------|
| `SELECT *` on 10M rows | $47K AWS bill | ✅ PERF-SCAN-001 |
| `DELETE FROM users` (no WHERE) | Total data loss | ✅ REL-DATA-001 |
| `EXEC(@sql + @input)` | SQL injection breach | ✅ SEC-INJ-002 |
| `LIKE '%search%'` | 5-second page loads | ✅ PERF-IDX-002 |
| Unrestricted PII access | GDPR violation | ✅ COMP-GDPR-001 |

**171 detection patterns** across 6 critical dimensions, catching issues **before they hit production**.

---

## 📦 Installation

```bash
# Recommended (isolated environment)
pipx install slowql

# Standard
pip install slowql

# Verify
slowql --version
```

Requirements: Python 3.11+ · Linux/macOS/Windows · Zero external dependencies

## ⚡ Quick Start

### Analyze SQL Files
```bash
# Create test file
cat > test.sql << 'EOF'
SELECT * FROM users WHERE email LIKE '%@gmail.com';
DELETE FROM logs;
UPDATE users SET password = 'admin123' WHERE id = 1;
EOF

# Run analysis
slowql --input-file test.sql
```

### Interactive Mode
```bash
slowql
```

### CI/CD Mode
```bash
slowql --non-interactive --input-file sql/ --export json
```

## 🔍 Detection Capabilities

### 171 Active Rules

| Dimension | Rules | Examples |
|-----------|-------|----------|
| 🔒 Security | 45 | SQL injection, hardcoded secrets, privilege escalation, xp_cmdshell |
| ⚡ Performance | 39 | SELECT *, N+1, non-SARGable, cartesian joins, deep pagination |
| 💰 Cost | 20 | Full scans, cross-region transfers, unbounded aggregations |
| 🛡️ Reliability | 19 | Missing WHERE, DROP without CASCADE, transaction safety |
| 📋 Compliance | 18 | GDPR violations, PII exposure, audit gaps |
| 📝 Quality | 30 | Code style, naming, deprecated syntax |

### Detection Examples

#### 🔒 Security: SQL Injection
```sql
-- ❌ CRITICAL: Dynamic SQL
EXEC('SELECT * FROM users WHERE id = ' + @userId);

-- ❌ HIGH: Tautological condition
SELECT * FROM users WHERE username = 'admin' OR 1=1;

-- ❌ HIGH: Time-based injection
SELECT * FROM data WHERE id = 1 AND SLEEP(5);
```
*Rules: SEC-INJ-002, SEC-INJ-003, SEC-INJ-004*

#### ⚡ Performance: Index Killers
```sql
-- ❌ Function on indexed column
SELECT * FROM users WHERE LOWER(email) = 'john@example.com';

-- ❌ Leading wildcard
SELECT * FROM users WHERE email LIKE '%@gmail.com';

-- ❌ Implicit type conversion
SELECT * FROM users WHERE user_id = '123';  -- user_id is INT
```
*Rules: PERF-IDX-001, PERF-IDX-002, PERF-IDX-003*

#### 🛡️ Reliability: Data Loss
```sql
-- ❌ CRITICAL: Deletes entire table
DELETE FROM users;

-- ❌ CRITICAL: Unbounded update
UPDATE users SET status = 'inactive';
```
*Rules: REL-DATA-001, PERF-BATCH-001*

## 🎨 Terminal Experience

### Features
- 🎯 **Health Score**: 0-100 with visual gauge
- 🔥 **Severity Heat Map**: Issue distribution matrix
- 📊 **Impact Zones**: Performance/Security/Cost breakdown
- 🎭 **Matrix Animations**: Cyberpunk-inspired UI
- ⌨️ **Keyboard Navigation**: Arrow keys & shortcuts

### Keyboard Shortcuts
| Key | Action |
|-----|--------|
| ↑/↓ | Navigate |
| Enter | Select |
| q/Esc | Cancel |
| A | Analyze more |
| E | Export |
| X | Exit |

## 📊 Export Formats

```bash
# Single format
slowql --input-file sql/ --export json

# Multiple formats
slowql --input-file sql/ --export json html csv

# Custom output directory
slowql --input-file sql/ --export json --out ./reports
```

### JSON (CI/CD Integration)
```json
{
  "statistics": {
    "total_issues": 28,
    "by_severity": {"CRITICAL": 2, "HIGH": 10, "MEDIUM": 12, "LOW": 4},
    "by_dimension": {"security": 8, "performance": 15, "cost": 3}
  },
  "issues": [...]
}
```

### HTML (Shareable Reports)
- Interactive single-page report
- Dark neon theme
- Print-friendly layout
- Embedded statistics

### CSV (Spreadsheet Analysis)
```csv
severity,rule_id,dimension,message,impact,fix_guidance,location
CRITICAL,SEC-INJ-001,security,"SQL injection detected","Data breach","Use parameterized queries",line 5
```

## 🔧 CLI Reference
```bash
# Input
slowql queries.sql                      # File
slowql --input-file sql/                # Directory
slowql --mode paste                     # Interactive paste
slowql --mode compose                   # Built-in editor
slowql --compare                        # Compare queries

# Output
slowql --export json html csv           # Export formats
slowql --out ./reports                  # Output directory
slowql --verbose                        # Detailed output

# UI
slowql --no-intro                       # Skip animation
slowql --fast                           # Minimal animations
slowql --non-interactive                # CI/CD mode
```

## 🚀 CI/CD Integration

### GitHub Actions
```yaml
name: SQL Quality Gate
on: [push, pull_request]

jobs:
  sql-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      
      - name: Install & Analyze
        run: |
          pip install slowql
          slowql --non-interactive --input-file sql/ --export json
      
      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: slowql-reports
          path: reports/
      
      - name: Quality Gate
        run: |
          python -c "
          import json, sys
          from pathlib import Path
          data = json.loads(sorted(Path('reports').glob('*.json'))[-1].read_text())
          critical = data['statistics']['by_severity'].get('CRITICAL', 0)
          if critical > 0:
              print(f'❌ {critical} CRITICAL issues')
              sys.exit(1)
          print('✅ No critical issues')
          "
```

### GitLab CI
```yaml
sql-analysis:
  stage: test
  image: python:3.12-slim
  script:
    - pip install slowql
    - slowql --non-interactive --input-file sql/ --export json
  artifacts:
    paths: [reports/]
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: slowql
        name: SlowQL
        entry: slowql --non-interactive --export json
        language: system
        files: '\.(sql)$'
```

## 🐳 Docker
```bash
# Quick run
docker run --rm -v "$PWD:/work" makroumi/slowql \
  slowql --input-file /work/queries.sql

# With exports
docker run --rm -v "$PWD:/work" makroumi/slowql \
  slowql --input-file /work/sql/ --export json html --out /work/reports
```

### Docker Compose
```yaml
version: '3.8'
services:
  slowql:
    image: makroumi/slowql:latest
    volumes:
      - ./sql:/work/sql:ro
      - ./reports:/work/reports
    command: slowql --non-interactive --input-file sql/ --export json html --out reports/
```

## 🏗️ Architecture

### Performance
| File Size | Queries | Time | Memory |
|-----------|---------|------|--------|
| Small | < 100 | < 1s | ~50MB |
| Medium | 100-1K | 1-5s | ~80MB |
| Large | 1K-10K | 5-30s | ~150MB |

### Privacy
- ✅ **Zero network calls** - 100% offline
- ✅ **No telemetry** - zero data collection
- ✅ **Local processing** - SQL never leaves your machine
- ✅ **Open source** - fully auditable

## 🛠️ Development
```bash
# Setup
git clone https://github.com/makroumi/slowql.git
cd slowql
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Verify
pytest -q  # 873 tests

# Quality
ruff check . && mypy src/slowql/
```

### Project Structure
```text
src/slowql/
├── analyzers/      # 6 dimension analyzers
├── rules/          # 171 detection rules
│   ├── security/   # 45 rules
│   ├── performance/# 39 rules
│   ├── cost/       # 20 rules
│   ├── reliability/# 19 rules
│   ├── compliance/ # 18 rules
│   ├── quality/    # 30 rules
├── cli/            # Terminal UI
├── core/           # Analysis engine
├── parser/         # SQL parser
└── reporters/      # JSON/HTML/CSV
```

### Adding Rules
```python
# src/slowql/rules/security/my_rule.py
from slowql.rules.base import PatternRule
from slowql.core.models import Severity, Dimension

class MyRule(PatternRule):
    id = "SEC-CUSTOM-001"
    name = "My Custom Check"
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    pattern = r"\bDANGEROUS\b"
    message_template = "Dangerous pattern: {match}"
```

## 🗺️ Roadmap
| Version | Target | Features |
|---------|--------|----------|
| v1.4.0 | ✅ Current | 171 rules, modular architecture, premium UI |
| v1.5.0 | Q2 2026 | VS Code extension, inline analysis |
| v1.6.0 | Q3 2026 | Advanced AST, query complexity metrics |
| v2.0.0 | Q4 2026 | Enterprise: custom rule packs, team dashboards |

## 🤝 Contributing
```bash
# Fork → Clone → Branch
git checkout -b feat/amazing-feature

# Develop
pip install -e ".[dev]"
pytest -q
ruff check .

# Submit PR
See CONTRIBUTING.md for full guidelines.
```

## 📜 License
Apache 2.0 — Free for commercial and non-commercial use. See LICENSE.

## 📞 Support
- 🐛 **Issues**: [GitHub Issues](https://github.com/makroumi/slowql/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/makroumi/slowql/discussions)

<p align="center"> <strong>Stop bad SQL before it costs you money.</strong> <br><br> Made with ❤️ by <a href="https://github.com/makroumi">@makroumi</a> <br><br> <a href="#slowql">⬆ Back to Top</a> </p>

---

*Happy SQL analyzing! 🎯*
