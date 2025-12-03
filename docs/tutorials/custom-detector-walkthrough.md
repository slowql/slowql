# Custom Detector Walkthrough

This tutorial shows how to build a custom detector step by step.

---

## 🧱 Create Detector File

Add `slowql/detectors/no_delete.py`:

```code
from slowql.detectors.base import Detector, Finding

class NoDeleteDetector(Detector):
    def analyze(self, query: str):
        if "DELETE" in query.upper():
            yield Finding(
                category="safety",
                severity="high",
                message="DELETE statements are not allowed.",
                suggestion="Use soft deletes or archive instead."
            )
```

---

## 🔗 Register Detector

Edit `slowql/detectors/__init__.py`:

```code
from .no_delete import NoDeleteDetector
DETECTORS.append(NoDeleteDetector)
```

---

## 🧪 Test Detector

Add `tests/unit/detectors/test_no_delete.py`:

```code
def test_no_delete_detector():
    detector = NoDeleteDetector()
    findings = list(detector.analyze("DELETE FROM users"))
    assert findings
```

---

## 📂 Config Example

```toml
[detectors.no_delete]
enabled = true
severity = "high"
```
