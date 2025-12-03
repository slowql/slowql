# Adding Detectors

This guide explains how to add new detectors to SlowQL. Detectors are rules that analyze SQL queries for performance, security, or style issues.

---

## 🧩 Detector Basics

A detector consists of:
- **Name** → Identifier for the detector  
- **Category** → Performance, Security, or Style  
- **Severity** → Critical, High, Medium, or Low  
- **Message** → Explanation of the issue  
- **Suggestion** → Recommended fix  

---

## 📂 Create a Detector File

Add a new detector definition in the `slowql/detectors/` directory.

```code
# slowql/detectors/select_star.py
from slowql.detectors.base import Detector

class SelectStarDetector(Detector):
    name = "select_star"
    category = "performance"
    severity = "medium"
    message = "Avoid SELECT * for clarity and performance."
    suggestion = "Specify column names explicitly."

    def detect(self, query_ast):
        return query_ast.has_select_star()
```

---

## ⚙️ Register the Detector

Update the detector registry so SlowQL knows about your new rule.

```code
# slowql/detectors/__init__.py
from .select_star import SelectStarDetector

DETECTORS = [
    SelectStarDetector(),
    # other detectors...
]
```

---

## 🧪 Test Your Detector

Add unit tests in `tests/unit/detectors/`:

```code
def test_select_star_detector():
    query = "SELECT * FROM customers;"
    findings = run_detectors(query)
    assert any(f.detector == "select_star" for f in findings)
```

Run tests:

```Bash
pytest tests/unit/detectors
```

---

## 📋 Document the Detector

Update the documentation in `docs/detectors/` with:
- Detector name  
- Example query  
- Suggested fix  
- Severity level  

---

## 🧠 Best Practices

- Keep detectors small and focused  
- Use realistic SQL samples in tests  
- Assign severity consistently  
- Document why the detector exists  
- Ensure detectors run fast for CI/CD pipelines  

---

## 🔗 Related Pages

- [Testing](testing.md)  
- [Contributing](contributing.md)  
- [Critical Detectors](../detectors/critical-detectors.md)  
- [Custom Detectors](../detectors/custom-detectors.md)  
