# Testing

This guide explains how to run and extend tests for SlowQL. It covers unit tests, integration tests, coverage, and CI validation.

---

## 🧪 Run All Tests

```Bash
pytest
```

This runs all tests in the `tests/` directory using the default configuration.

---

## 🧩 Test Structure

- `tests/unit/` → Tests for individual components (parser, detectors, CLI)  
- `tests/integration/` → End‑to‑end tests using real SQL files  
- `tests/data/` → Sample SQL files used in tests  
- `conftest.py` → Shared fixtures and test setup  

---

## 🧼 Linting and Type Checks

Run lint and type checks before committing:

```Bash
ruff check slowql tests  
mypy slowql
```

---

## 📊 Coverage Report

Generate a coverage report:

```Bash
pytest --cov=slowql --cov-report=term-missing
```

You’ll see which lines are untested and where to improve coverage.

---

## 🧪 CI Validation

SlowQL uses GitHub Actions to validate every push and pull request:

- Lint  
- Type check  
- Unit + integration tests  
- Docs build (strict mode)

You can preview the same checks locally:

```Bash
make test-all
```

---

## 🧠 Best Practices

- Write tests for every new detector  
- Use realistic SQL samples in `tests/data/`  
- Keep unit tests fast and isolated  
- Use `pytest.mark.parametrize` for edge cases  
- Run `pytest` before every commit

---

## 🔗 Related Pages

- [Setup](setup.md)  
- [Contributing](contributing.md)  
- [Adding Detectors](adding-detectors.md)  
