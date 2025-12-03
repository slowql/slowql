# GitHub Actions

This example shows how to run SlowQL inside a GitHub Actions workflow to automatically analyze SQL files on every push or pull request.

---

## 📂 Workflow File

Create `.github/workflows/slowql.yml`:

```code
name: SlowQL Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"
      - name: Install SlowQL
        run: pip install slowql
      - name: Run Analysis
        run: |
          slowql --no-intro --fast --input-file sample.sql --export json --output results.json
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

The workflow will generate `results.json` containing all detector findings. You can upload it as an artifact or parse it in later steps.

---

## 🧠 Best Practices

- Use `--no-intro` to keep logs clean  
- Use `--fast` for quicker CI runs  
- Export to JSON for machine‑readable output  
- Add `slowql.yml` to all SQL‑heavy repos  

---

## 🔗 Related Examples

- [Basic Usage](basic-usage.md)  
- [GitLab CI](gitlab-ci.md)  
- [Jenkins](jenkins.md)  
- [Pre-Commit Hook](pre-commit-hook.md)  
