# CI/CD Integration

SlowQL can be integrated into CI/CD pipelines to automatically catch expensive queries before they reach production. This page shows how to configure SlowQL in common environments.

---

## ⚙️ General CI/CD Usage

Run SlowQL in fast mode with clean logs:

```Bash
slowql --no-intro --fast --input-file queries.sql --export json --output results.json
```

This ensures machine‑readable output and avoids animations that clutter logs.

---

## 🔄 GitHub Actions

Add SlowQL to a GitHub Actions workflow:

```code
name: SlowQL Analysis
on: [push, pull_request]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run SlowQL
        run: |
          pip install slowql
          slowql --no-intro --fast --input-file queries.sql --export json --output results.json
```

---

## 📦 GitLab CI

Integrate SlowQL into GitLab CI:

```code
slowql-analysis:
  image: python:3.11
  script:
    - pip install slowql
    - slowql --no-intro --fast --input-file queries.sql --export json --output results.json
```

---

## 🛠 Jenkins Pipeline

Add SlowQL to a Jenkins pipeline stage:

```code
pipeline {
  agent any
  stages {
    stage('SlowQL Analysis') {
      steps {
        sh '''
          pip install slowql
          slowql --no-intro --fast --input-file queries.sql --export json --output results.json
        '''
      }
    }
  }
}
```

---

## 🧩 Pre-Commit Hook

You can run SlowQL before commits to prevent bad queries from entering source control:

```code
repos:
  - repo: local
    hooks:
      - id: slowql
        name: SlowQL Analysis
        entry: slowql --no-intro --fast --input-file queries.sql
        language: system
```

---

## 🔗 Related Pages

- [CLI Reference](cli-reference.md)  
- [File Analysis](file-analysis.md)  
- [Export Formats](export-formats.md)  
