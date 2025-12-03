# Performance

This guide explains how to optimize SlowQL’s performance in local runs and CI/CD pipelines. It covers CLI flags, detector tuning, and workflow strategies.

---

## ⚡ Fast Mode

Use `--fast` to skip deep checks and speed up analysis:

```Bash
slowql --fast --input-file queries.sql
```

---

## 🛑 Disable Animations

Suppress banners and animations in CI/CD logs:

```Bash
slowql --no-intro --fast --input-file queries.sql
```

---

## 🧩 Detector Tuning

Disable non‑critical detectors in `.slowql.toml` to reduce runtime:

```toml
[detectors.select_star]
enabled = false
```

---

## 🧪 Parallel Workflows

Split jobs in CI/CD for faster feedback:

- Lint → Ruff  
- Type check → Mypy  
- Test → Pytest  
- Docs → MkDocs strict build  
- SlowQL → SQL analysis  

---

## 📂 Sample CI/CD Config

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

## 🧠 Best Practices

- Use `--fast` for quick checks, full mode for releases  
- Disable detectors not relevant to your project  
- Run SlowQL in parallel with other jobs  
- Cache Python dependencies in CI/CD  
- Keep SQL files small and modular for faster parsing  

---

## 🔗 Related Pages

- [Common Issues](common-issues.md)  
- [FAQ](faq.md)  
- [Security Best Practices](../security/best-practices.md)  
