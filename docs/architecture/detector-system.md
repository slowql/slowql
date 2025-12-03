# Detector System

## Overview
The detector system is the heart of SlowQL. It applies rule‑based checks to SQL queries to identify performance and security issues.

---

## Design Pattern
- **Strategy Pattern**: Each detector encapsulates one detection strategy.
- **Base Class**: `BaseDetector` defines the interface (`detect(query) -> List[Issue]`).
- **Auto‑registration**: Detectors are registered via a decorator, so new detectors are automatically discovered.
- **Parallel Execution**: Detectors run in a thread pool for scalability.

---

## Detector Lifecycle
1. **Definition**  
   - Create a new class inheriting from `BaseDetector`.
   - Implement the `detect` method.
2. **Registration**  
   - Use the `@register_detector` decorator.
   - Detector is added to the global registry.
3. **Execution**  
   - Analyzer iterates over all registered detectors.
   - Each detector runs independently, returning a list of `Issue` objects.
4. **Aggregation**  
   - Results are collected and merged into a unified report.

---

## Example Detector

```python
from slowql.detectors.base import BaseDetector, register_detector
from slowql.issue import Issue

@register_detector
class MissingWhereDetector(BaseDetector):
    """Detects queries missing a WHERE clause."""

    def detect(self, query: str) -> list[Issue]:
        if "SELECT" in query.upper() and "WHERE" not in query.upper():
            return [Issue(
                severity="high",
                message="Query missing WHERE clause",
                detector="MissingWhereDetector"
            )]
        return []
```

## Detector Categories

### Security Detectors
- SQL Injection patterns  
- Missing WHERE clause  
- Unsafe string concatenation  

### Performance Detectors
- `SELECT *` usage  
- Non‑SARGable conditions  
- Unindexed joins  

---

## Extensibility
Adding a new detector requires only:
- A new class  
- A decorator  
- No changes to the analyzer core  

Detectors can be grouped by category for reporting.

---

## Best Practices
- Keep detectors **stateless**  
- Ensure detectors run in **<10ms** for typical queries  
- Write unit tests for each detector  
- Document detector purpose in `docs/development/ADDING_DETECTORS.md`  
