# Team Onboarding Guide

This tutorial helps new team members get started with SlowQL.

---

## 📦 Install

```Bash
pip install slowql
```

---

## 📂 Clone Repo

```Bash
git clone https://github.com/org/project.git
cd project
```

---

## ⚙️ Config

Ensure `.slowql.toml` is present:

```toml
[detectors.select_star]
severity = "medium"
message = "Avoid SELECT *"
```

---

## 🚀 Run Analysis

```Bash
slowql --no-intro --fast --input-file sample.sql --export json --output results.json
```

---

## 📤 CI/CD

Explain pipeline integration (GitHub, GitLab, Jenkins).  
Artifacts are archived for compliance.

---

## 🧠 Best Practices

- Always run SlowQL before committing  
- Review findings in CI/CD logs  
- Document detector rationale for onboarding  
