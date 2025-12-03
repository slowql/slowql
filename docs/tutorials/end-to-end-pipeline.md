# End-to-End Pipeline Tutorial

This tutorial walks through setting up SlowQL from installation to CI/CD integration.

---

## 📦 Install SlowQL

```Bash
pip install slowql
```

---

## 🧪 Create Detector Config

```toml
[detectors.select_star]
severity = "medium"
message = "Avoid SELECT *"
suggestion = "Specify columns explicitly."
```

---

## 🚀 Run Locally

```Bash
slowql --no-intro --fast --input-file sample.sql --export json --output results.json
```

---

## ⚙️ CI/CD Integration

Example GitHub Actions workflow:

```code
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run SlowQL
        run: slowql --no-intro --fast --input-file sample.sql --export json --output results.json
```

---

## 📤 Export Results

Artifacts (`results.json`) can be archived for compliance and debugging.

---
