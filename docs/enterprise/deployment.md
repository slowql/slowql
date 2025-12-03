# Deployment

This guide explains how to deploy SlowQL in enterprise environments, including local setups, CI/CD pipelines, Docker containers, and internal developer portals.

---

## 🧱 Local Installation

```Bash
pip install slowql
```

Run analysis:

```Bash
slowql --input-file queries.sql --export json --output results.json
```

---

## 🐳 Docker Deployment

Use the official Docker image:

```Bash
docker run --rm -v $(pwd):/data slowql/cli \
  --input-file /data/queries.sql \
  --export json --output /data/results.json
```

---

## ⚙️ CI/CD Integration

SlowQL integrates with:

- GitHub Actions → `.github/workflows/slowql.yml`  
- GitLab CI → `.gitlab-ci.yml`  
- Jenkins → `Jenkinsfile`  
- Pre-commit → `.pre-commit-config.yaml`

Use `--no-intro` and `--fast` for clean, fast CI runs.

---

## 🧪 Internal Developer Portals

Embed SlowQL into internal tools:

- Wrap CLI in a web interface  
- Use exported JSON for dashboards  
- Schedule scans on SQL-heavy repos  
- Share detector configs across teams

---

## 📂 Config Management

Store `.slowql.toml` in version control:

```toml
[detectors.select_star]
category = "performance"
severity = "medium"
message = "Avoid SELECT *"
suggestion = "Specify columns explicitly."
```

---

## 🧠 Best Practices

- Use Docker for reproducible builds  
- Run in CI before every merge  
- Export results for audit and compliance  
- Share configs across teams  
- Document detector rationale for onboarding

---

## 🔗 Related Pages

- [Overview](overview.md)  
- [Team Features](team-features.md)  
- [Support](support.md)  
