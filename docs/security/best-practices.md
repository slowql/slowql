# Security Best Practices

This guide outlines best practices for using and deploying SlowQL securely. It covers safe query handling, CI/CD hygiene, and detector configuration.

---

## 🔐 Safe Query Handling

- Never analyze queries containing live secrets or credentials  
- Use sample or anonymized SQL files for testing  
- Avoid dynamic SQL unless properly sanitized  
- Prefer parameterized queries over string concatenation

---

## 🧪 CI/CD Hygiene

- Use `--no-intro` to suppress banners in logs  
- Use `--fast` for quick scans in pipelines  
- Export results in `json` for machine‑readable output  
- Store detector configs in `.slowql.toml` under version control

---

## 🛡 Detector Configuration

Use `.slowql.toml` to enforce security rules:

```toml
[detectors.sql_injection]
category = "security"
severity = "critical"
message = "Unsafe string concatenation detected."
suggestion = "Use parameterized queries."
```

---

## 📤 Artifact Management

- Do not commit `results.json` to public repos  
- Use CI artifacts for internal review only  
- Rotate credentials if any sensitive queries are exposed

---

## 🧠 Best Practices

- Run SlowQL in isolated environments  
- Validate detector coverage with real‑world samples  
- Review findings before deployment  
- Use custom detectors to enforce team‑specific security rules  
- Keep SlowQL updated to benefit from new security checks

---

## 🔗 Related Pages

- [Security Policy](security-policy.md)  
- [Vulnerability Reporting](vulnerability-reporting.md)  
- [Custom Detectors](../detectors/custom-detectors.md)  
