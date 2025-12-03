# FAQ

This page answers frequently asked questions about SlowQL, including usage, configuration, detectors, and CI/CD integration.

---

## ❓ What does SlowQL do?

SlowQL performs static analysis on SQL files to detect performance, security, and style issues using configurable detectors.

---

## ❓ Does it connect to a database?

No. SlowQL parses SQL files locally and does not execute queries or connect to any database.

---

## ❓ What formats can I export results in?

You can export findings in `json`, `csv`, or `html`:

```Bash
slowql --export json --output results.json
```

---

## ❓ How do I disable a detector?

Use `.slowql.toml` to disable or override detectors:

```toml
[detectors.select_star]
enabled = false
```

---

## ❓ Can I write my own detectors?

Yes. Add a new class in `slowql/detectors/`, register it in `__init__.py`, and write tests in `tests/unit/detectors/`.

---

## ❓ How do I use SlowQL in CI/CD?

Use `--no-intro` and `--fast` for clean, fast runs. See examples for GitHub Actions, GitLab CI, Jenkins, and pre-commit.

---

## ❓ What Python version is required?

Python 3.11 or higher is recommended.

---

## ❓ Can I run SlowQL in Docker?

Yes. Use the official image or build your own:

```Bash
docker run --rm -v $(pwd):/data slowql/cli \
  --input-file /data/sample.sql --export json --output /data/results.json
```

---

## ❓ Where can I report bugs?

Open a GitHub Issue or submit a security advisory for sensitive vulnerabilities.

---

## 🔗 Related Pages

- [Common Issues](common-issues.md)  
- [Performance](performance.md)  
- [Security Policy](../security/security-policy.md)  
