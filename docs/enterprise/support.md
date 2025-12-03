# Support

This page explains how enterprise teams can access support for SlowQL, including documentation, community channels, and dedicated enterprise assistance.

---

## 📚 Documentation

- Full reference available in the `docs/` portal  
- Architecture, detectors, and CI/CD examples included  
- Strict builds with revision tracking ensure docs are always up to date  

---

## 👥 Community Support

- GitHub Issues → Report bugs, request features, ask questions  
- Discussions → Share workflows, detector configs, and CI/CD setups  
- Contributions → Submit PRs to improve detectors, docs, or tooling  

---

## 🛡 Enterprise Support

For enterprise customers:
- Dedicated support channels (email or private portal)  
- Priority bug triage and patch releases  
- Assistance with CI/CD integration and onboarding  
- Guidance on custom detector design and compliance rules  

---

## 🧪 Self-Service Tools

- Run `slowql --help` for CLI usage  
- Use `--no-intro` and `--fast` for CI/CD pipelines  
- Export results in JSON/CSV/HTML for audit and debugging  
- Store `.slowql.toml` in version control for shared configs  

---

## 📤 Reporting Issues

```Bash
git clone https://github.com/makroumi/slowql.git
cd slowql
gh issue create --title "Bug: Detector misfire" --body "Steps to reproduce..."
```

---

## 🧠 Best Practices

- Check documentation before filing issues  
- Provide reproducible SQL samples when reporting bugs  
- Use private channels for sensitive security disclosures  
- Keep detector configs documented for team onboarding  

---

## 🔗 Related Pages

- [Overview](overview.md)  
- [Deployment](deployment.md)  
- [Team Features](team-features.md)  
- [Security Policy](../security/security-policy.md)  
