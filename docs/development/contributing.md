# Contributing

We welcome contributions to SlowQL! This guide explains how to propose changes, follow coding standards, and submit pull requests.

---

## 🧱 Contribution Workflow

1. **Fork the repository**  
2. **Clone your fork locally**  
3. **Create a feature branch**  
4. **Make changes and add tests**  
5. **Run lint, type checks, and tests**  
6. **Commit with a clear message**  
7. **Push your branch**  
8. **Open a pull request (PR)**

---

## 📦 Clone and Branch

```Bash
git clone https://github.com/makroumi/slowql.git  
cd slowql  
git checkout -b feature/my-detector
```

---

## 🧼 Code Standards

- Python 3.11+  
- Ruff for linting  
- Mypy for type checking  
- Pytest for tests  
- MkDocs Material for documentation  

Run checks locally:

```Bash
ruff check slowql tests  
mypy slowql  
pytest
```

---

## 📋 Commit Messages

Follow conventional commit style:

- `feat:` → New feature  
- `fix:` → Bug fix  
- `docs:` → Documentation changes  
- `test:` → Adding or updating tests  
- `chore:` → Maintenance tasks  

Example:

```Bash
git commit -m "feat(detectors): add select_star detector"
```

---

## 🧪 Pull Requests

- Include a description of changes  
- Reference related issues  
- Ensure CI passes (lint, type, tests, docs)  
- Add documentation for new features  

---

## 🧠 Best Practices

- Keep PRs small and focused  
- Write tests for all new detectors  
- Document changes in `CHANGELOG.md`  
- Use draft PRs for work in progress  
- Engage in code review discussions  

---

## 🔗 Related Pages

- [Setup](setup.md)  
- [Testing](testing.md)  
- [Adding Detectors](adding-detectors.md)  
- [Release Process](release-process.md)  
