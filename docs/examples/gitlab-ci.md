# GitLab CI

This example shows how to run SlowQL inside a GitLab CI pipeline to automatically analyze SQL files on every commit or merge request.

---

## 📂 Pipeline Configuration

Create `.gitlab-ci.yml`:

```code
stages:
  - analyze

slowql-analysis:
  stage: analyze
  image: python:3.11
  before_script:
    - pip install slowql
  script:
    - slowql --no-intro --fast --input-file sample.sql --export json --output results.json
  artifacts:
    paths:
      - results.json
    expire_in: 1 week
```

---

## 📦 Sample SQL File

Include a file like `sample.sql` in your repo:

```code
SELECT * FROM users WHERE email LIKE '%@gmail.com';  
DELETE FROM orders;
```

---

## 📤 Exported Results

The pipeline will generate `results.json` containing all detector findings. It will be stored as an artifact for later inspection.

---

## 🧠 Best Practices

- Use `--no-intro` for clean CI logs  
- Use `--fast` for quicker runs  
- Export to JSON for machine‑readable results  
- Store artifacts for debugging and compliance  

---

## 🔗 Related Examples

- [Basic Usage](basic-usage.md)  
- [GitHub Actions](github-actions.md)  
- [Jenkins](jenkins.md)  
- [Pre-Commit Hook](pre-commit-hook.md)  
