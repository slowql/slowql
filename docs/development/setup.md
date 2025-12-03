# Setup

This guide explains how to set up SlowQL for local development, testing, and contribution. It covers environment setup, dependencies, and project structure.

---

## 🧱 Prerequisites

- Python 3.11+  
- Git  
- Docker (optional, for container testing)  
- Node.js (optional, for docs preview)

---

## 📦 Clone the Repository

# Bash
git clone https://github.com/makroumi/slowql.git  
cd slowql

---

## 🧪 Create Virtual Environment

```Bash
python -m venv .venv  
source .venv/bin/activate
```

---

## 📥 Install Dependencies

```Bash
pip install -e .[dev]
```

This installs SlowQL in editable mode with all dev/test dependencies.

---

## 📂 Project Structure

- `slowql/` → Core engine and CLI  
- `tests/` → Unit and integration tests  
- `docs/` → MkDocs documentation  
- `.github/` → CI workflows  
- `pyproject.toml` → Build and dependency config  
- `.slowql.toml` → Optional config for detectors

---

## 🧪 Verify Setup

```Bash
slowql --version  
pytest
```

---

## 🔗 Related Pages

- [Testing](testing.md)  
- [Contributing](contributing.md)  
- [Adding Detectors](adding-detectors.md)  
