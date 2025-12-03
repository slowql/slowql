# Release Process

This guide explains how to prepare and publish a new release of SlowQL. It covers versioning, changelog updates, packaging, and distribution.

---

## 🧱 Versioning

SlowQL follows **semantic versioning** (`MAJOR.MINOR.PATCH`):

- **MAJOR** → Breaking changes  
- **MINOR** → New features, backwards‑compatible  
- **PATCH** → Bug fixes, small improvements  

Update the version in `pyproject.toml`:

```toml
[project]
version = "1.2.0"
```

---

## 📋 Update Changelog

Document changes in `CHANGELOG.md`:

```code
## [1.2.0] - 2025-12-03
### Added
- New detector for unsafe dynamic SQL
### Fixed
- Parser bug with nested subqueries
```

---

## 🧪 Run Validation

Before releasing, ensure all checks pass:

```Bash
ruff check slowql tests  
mypy slowql  
pytest  
mkdocs build --strict
```

---

## 📦 Build Package

```Bash
python -m build
```

This generates distribution files in `dist/`.

---

## 🚀 Publish to PyPI

Upload the package:

```Bash
twine upload dist/*
```

---

## 🔄 GitHub Release

1. Tag the release:

```Bash
git tag v1.2.0  
git push origin v1.2.0
```

2. Create a GitHub release with notes from `CHANGELOG.md`.

---

## 🧠 Best Practices

- Keep releases small and frequent  
- Always update documentation with new features  
- Ensure detectors are well‑tested before release  
- Use draft releases for staging  
- Automate with CI/CD where possible  

---

## 🔗 Related Pages

- [Contributing](contributing.md)  
- [Setup](setup.md)  
- [Testing](testing.md)  
- [Adding Detectors](adding-detectors.md)  
