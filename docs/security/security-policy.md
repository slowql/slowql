# Security Policy

This document outlines SlowQL’s security policy, including how vulnerabilities are handled, how users can report issues, and what guarantees are made about data safety.

---

## 🔐 Scope

This policy applies to:
- The SlowQL CLI and parser engine  
- All built‑in and custom detectors  
- CI/CD integrations and exported reports  
- Documentation and public repositories  

---

## 🧪 Data Handling

- SlowQL performs **static analysis only** — it does not connect to databases  
- SQL files are parsed locally; no query execution occurs  
- No telemetry or data collection is performed by default  
- Exported results (e.g. `results.json`) are stored locally unless explicitly uploaded

---

## 🛡 Vulnerability Management

- Vulnerabilities are tracked and triaged via GitHub Issues  
- Critical issues are patched within 72 hours  
- Security fixes are released as patch versions (`x.y.Z`)  
- Contributors must follow secure coding practices (see `best-practices.md`)

---

## 📢 Reporting Issues

If you discover a vulnerability:
- Do **not** disclose it publicly  
- Email the maintainer or open a private GitHub security advisory  
- Include reproduction steps and affected versions  
- You will receive a response within 48 hours

---

## 🧠 Maintainer Responsibilities

- Review all security reports promptly  
- Patch and release fixes quickly  
- Keep dependencies up to date  
- Audit detectors for unsafe patterns  
- Maintain strict CI/CD validation for every release

---

## 🔗 Related Pages

- [Best Practices](best-practices.md)  
- [Vulnerability Reporting](vulnerability-reporting.md)  
- [Custom Detectors](../detectors/custom-detectors.md)  
