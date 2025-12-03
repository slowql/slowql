# Basic Usage

This example shows how to run SlowQL on a SQL file and interpret the results. It’s ideal for first‑time users or quick local analysis.

---

## 📂 Sample SQL File

Create a file called `sample.sql`:

```code
SELECT * FROM users WHERE email LIKE '%@gmail.com';  
DELETE FROM orders;
```

---

## 🚀 Run SlowQL

```Bash
slowql --input-file sample.sql
```

You’ll see output in the terminal showing detected issues, severity levels, and suggestions.

---

## 📤 Export Results

To save results in JSON format:

```Bash
slowql --input-file sample.sql --export json --output results.json
```

Other formats: `csv`, `html`

---

## ⚙️ Fast Mode

Run a quick scan without deep checks:

```Bash
slowql --fast --input-file sample.sql
```

---

## 🧪 CI/CD Safe Mode

Disable animations and export clean logs:

```Bash
slowql --no-intro --fast --input-file sample.sql --export json --output results.json
```

---

## 🔗 Related Examples

- [GitHub Actions](github-actions.md)  
- [GitLab CI](gitlab-ci.md)  
- [Jenkins](jenkins.md)  
- [Pre-Commit Hook](pre-commit-hook.md)  
