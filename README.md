# 🔥 SLOWQL: The Performance Sentinel for SQL

## 💥 Stop Shipping Bad SQL. Ship Confidence.

**SLOWQL** is the cinematic, developer-first static SQL analyzer that turns your codebase into a performance fortress. Stop wasting engineering cycles debugging production issues. Start analyzing, detecting, and fixing performance anti-patterns, dangerous constructs, and maintainability issues *before* they even merge.

Designed for engineers who treat tooling as craft: beautiful, feature-rich CLI output, deterministic builds, and seamless CI/CD integration.

---

## 🔗 Badges 

<!-- Replace the placeholders below with actual badge URLs -->

[![PyPI Version](https://img.shields.io/pypi/v/slowql.svg)](https://pypi.org/project/slowql/)
[![GHCR Image](https://img.shields.io/github/v/tag/ORG/slowql?label=GHCR&logo=docker)](https://github.com/<ORG>/slowql/pkgs/container/slowql)
[![License](https://img.shields.io/github/license/<ORG>/slowql)](LICENSE)

---

## ⚡️ Quick Installation (Get Running in 60 Seconds)

We recommend using `pipx` for isolated, clean installs. No dependency conflicts, just pure performance analysis.

### The Recommended Path: Pipx (Isolated)

```bash
# 1. Install pipx (if you haven't already)
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# 2. Install SLOWQL
pipx install slowql

# 3. Verify
slowql --help
```

### The Fastest Path: Pip (Global)

```Bash
python3 -m pip install --user slowql
slowql --help
```


### The CI/Ops Path: Docker (Zero Dependencies)
Run the container image directly for instant execution—no Python required.
```Bash
docker run --rm ghcr.io/<ORG>/slowql:latest --help
```
## ⚙️ Why SLOWQL? 

| Feature | Description | Impact |
| :--- | :--- | :--- |
| **Severity Detectors** | Multi-level analysis: `Critical`, `High`, `Medium`, `Low`. | Prioritize the fixes that matter most for production stability. |
| **Cinematic CLI** | Stunning, vivid terminal output with optional ASCII effects. | Makes tooling feel like craft, not a chore. Use `--no-intro` for CI. |
| **Pipeline Ready** | Exports in `html`, `csv`, or machine-readable `json`. | Seamless integration into dashboards, reporting, and automated alerts. |
| **Deterministic Builds** | Reproducible results and Docker-ready, multi-arch images. | Reliable builds every time, across every architecture. |

## 🔬 Practical Usage

 ### 1. Generate a Rich HTML Report
 Analyze a file and output a rich, standalone HTML report for easy sharing and review.
 ```Bash
 slowql --input-file examples/sample.sql --export html --out ./report
 ```

### 2. CI/CD Pipeline Integration (JSON Export)
Use non-interactive mode for speed and export clean JSON for automated parsing.
```Bash
slowql --non-interactive --fast --input-file examples/sample.sql --export json --out ./report
```

### 3. Interactive Code Snippet Testing
Need to check a quick query? Use paste mode.
```Bash
slowql --mode paste
```

### 4. Programmatic Analysis (Python)
Integrate the core analysis engine directly into your Python scripts or custom tooling:

```Python
from slowql.core.analyzer import Analyzer

a = Analyzer()
# Analyze a query string directly
results = a.analyze("SELECT * FROM users WHERE id = 1")
print(results.summary())
```

## 🧑‍💻 Developer's Toolkit
### Build from SourceClone 
the repository and build the wheel locally.
```Bash
git clone [https://github.com/](https://github.com/)<ORG>/slowql.git
cd slowql
python3 -m pip install --upgrade build
python3 -m build
python3 -m pip install dist/slowql-*.whl
slowql --help
```
## Run in Editable Mode
Set up a virtual environment for making contributions and running tests locally.
```Bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
pytest
```

## CI / CD (The Shipping Standard)
We enforce strict CI/CD practices using GitHub Actions.

**Trigger a Release**: Update the version in 'pyproject.toml', commit, and push an annotated tag.
```Bashgit 
commit -am "chore(release): v1.0.2"
git tag -a v1.0.2 -m "release slowql v1.0.2"
git push origin main
git push origin v1.0.2
```
## 💖 Contributing
Contributions are highly valued. We are looking for experienced engineers who respect high standards of craft.

 - Fork, create a feature branch, and open a PR against main.
 - Every new detector or behavior change requires tests.
 - Keep commits small, focused, and ensure all CI checks pass.
## 🤝 Support & License

For technical issues, please open an issue on GitHub. For security-sensitive disclosures, use the repository security policy.

License: Apache-2.0 — see LICENSE for details.
 
**Copyright (c) 2025 El Mehdi Makroumi.**