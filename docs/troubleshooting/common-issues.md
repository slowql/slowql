# Common Issues

This guide lists frequent problems users encounter with SlowQL and how to resolve them. It covers CLI errors, detector misfires, CI/CD failures, and config mistakes.

---

## ❌ CLI Fails to Run

**Symptom:** `command not found: slowql`  
**Fix:** Ensure SlowQL is installed and in your PATH.

```Bash
pip install slowql
```

---

## ❌ Detector Doesn’t Trigger

**Symptom:** No findings for known bad query  
**Fix:** Check that the detector is registered in `slowql/detectors/__init__.py`  
Also verify `.slowql.toml` doesn’t disable it.

---

## ❌ CI/CD Job Fails

**Symptom:** CI logs show animation or banner output  
**Fix:** Use `--no-intro` to suppress CLI banners in CI.

```Bash
slowql --no-intro --fast --input-file sample.sql
```

---

## ❌ Exported File Missing

**Symptom:** `results.json` not found  
**Fix:** Ensure `--output` path is writable and `--export` format is valid (`json`, `csv`, `html`)

---

## ❌ Detector Config Ignored

**Symptom:** Custom severity or message not applied  
**Fix:** Check `.slowql.toml` formatting and location  
Use `[detectors.<name>]` blocks with correct keys

```toml
[detectors.select_star]
severity = "medium"
message = "Avoid SELECT *"
```

---

## ❌ MkDocs Build Fails

**Symptom:** `mkdocs build --strict` fails  
**Fix:** Check for broken links, missing headings, or invalid Markdown  
Use `--verbose` to debug

---

## 🧠 Best Practices

- Run `slowql --help` to verify CLI options  
- Use `pytest -v` to debug detector tests  
- Validate `.slowql.toml` with a linter  
- Use CI artifacts to inspect exported results  
- Keep sample SQL files realistic but safe

---

## 🔗 Related Pages

- [FAQ](faq.md)  
- [Performance](performance.md)  
- [Security Policy](../security/security-policy.md)  
