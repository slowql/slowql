# Pre-Commit Hook

This example shows how to integrate SlowQL into a pre‑commit workflow so SQL files are automatically analyzed before every commit.

---

## 📂 Install Pre-Commit

```Bash
pip install pre-commit
```

---

## ⚙️ Create Configuration

Add a `.pre-commit-config.yaml` file to your repo:

```code
repos:
  - repo: local
    hooks:
      - id: slowql
        name: SlowQL Analysis
        entry: slowql --no-intro --fast --input-file sample.sql --export json --output results.json
        language: system
        files: \.sql$
```

---

## 📦 Sample SQL File

Include a file like `sample.sql` in your repo:

```code
SELECT * FROM users WHERE email LIKE '%@gmail.com';  
DELETE FROM orders;
```

---

## 🚀 Run Pre-Commit

Install hooks:

```Bash
pre-commit install
```

Now every time you commit, SlowQL will run against staged `.sql` files.

---

## 📤 Exported Results

The hook will generate `results.json` containing detector findings. If issues are detected, the commit will fail until fixed.

---

## 🧠 Best Practices

- Use `--no-intro` for clean logs  
- Use `--fast` for quicker checks  
- Keep detector configs in `.slowql.toml` for consistency  
- Run `pre-commit run --all-files` to validate the entire repo  

---

## 🔗 Related Examples

- [Basic Usage](basic-usage.md)  
- [GitHub Actions](github-actions.md)  
- [GitLab CI](gitlab-ci.md)  
- [Jenkins](jenkins.md)  
