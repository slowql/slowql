# Team Features

SlowQL provides enterprise‑grade features designed for teams. These capabilities make collaboration, onboarding, and compliance easier across large organizations.

---

## 👥 Shared Configurations

Teams can share detector configurations via `.slowql.toml`:

```toml
[detectors.select_star]
category = "performance"
severity = "medium"
message = "Avoid SELECT *"
suggestion = "Specify columns explicitly."
```

Store this file in version control so all contributors use the same rules.

---

## 📂 Onboarding Documentation

- Provide new team members with a quickstart guide  
- Include sample SQL files and detector rationale  
- Document CI/CD integration steps  
- Use branded CLI output for consistency

---

## 🔄 CI/CD Integration

SlowQL supports parallel workflows for teams:

- Lint → Ruff  
- Type check → Mypy  
- Test → Pytest  
- Docs → MkDocs strict build  

```Bash
slowql --no-intro --fast --input-file queries.sql --export json --output results.json
```

---

## 🛡 Compliance and Audit

- Export results in JSON/CSV for audit trails  
- Archive findings in CI/CD artifacts  
- Use severity levels to prioritize fixes  
- Document detector rationale for compliance reviews

---

## 🚀 Collaboration Features

- Shared configs across repos  
- Pre‑commit hooks for consistent enforcement  
- CI/CD pipelines for automated validation  
- Documentation portals with revision tracking  

---

## 🧠 Best Practices

- Keep detector rules small and focused  
- Document why each rule exists  
- Use consistent severity levels across teams  
- Automate validation in CI/CD pipelines  
- Provide onboarding docs for new contributors  

---

## 🔗 Related Pages

- [Overview](overview.md)  
- [Deployment](deployment.md)  
- [Support](support.md)  
