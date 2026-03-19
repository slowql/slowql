# Testing Guidelines

SlowQL asserts an absolute operational confidence tier. Due to the high-risk environment static analyzers operate inside during continuous integration tracks, total test coverage across `ASTRule` structures is critically enforced preventing destructive deployment regressions.

## Pipeline Executions

We leverage the `pytest` orchestration network completely natively.

**Execute the full suite targeting multiple Python topologies:**
```bash
pytest
```

**Execute explicit modular targeting:**
```bash
pytest tests/unit/test_rules.py -v
```

## AST Test Harnessing

Whenever deploying a new generic `PatternRule` or AST structural modification (`ASTRule`), explicit unit tests verifying logical execution bounds are inherently mandated.

Tests should be segmented rigorously under `tests/`.

### The Core Mock Assistant
To bypass massive engine initialization layers, utilize standard model artifacts simulating an active SQL document.

```python
from slowql.core.models import Location, Query

_LOC = Location(line=1, column=1)

def _q(sql: str, dialect: str, query_type: str = "SELECT") -> Query:
    return Query(
        raw=sql, 
        normalized=sql, 
        dialect=dialect, 
        location=_LOC, 
        query_type=query_type
    )
```

For logic inheriting from `ASTRule`, `sqlglot` AST objects must be initialized inside the mock to accurately trigger the engine's deeper parser layers:

```python
import sqlglot

def _ast_q(sql: str, dialect: str) -> Query:
    try:
        ast = sqlglot.parse_one(sql)
    except Exception:
        ast = None
        
    return Query(
        raw=sql, 
        normalized=sql, 
        dialect=dialect, 
        location=_LOC, 
        query_type="SELECT", 
        ast=ast
    )
```

### Required Assertion Boundaries

Enterprise coverage relies completely on defining absolute structural checks during pull requests.

1. **True Positive Bounds:** Verify the rule aggressively identifies the explicit SQL syntax within its approved `Dialect` parameters.
2. **False Positive Bounds:** Provide natively secure syntax proving the engine does not improperly label mathematically equivalent structures as vulnerabilities.
3. **Dialect Segregation:** For dialect-restricted rules (e.g. `dialects = ("tsql",)`), assert the exact string payload provided against an unapproved dialect (e.g. `postgresql`) implicitly bypasses execution constraints gracefully.
4. **Resilient Assertions:** Because the internal rules framework routinely scales dynamically, never hardcode scalar quantities during catalog verification models:

**Correct Validation Schema:**
```python
assert len(get_all_rules()) >= 270
```

**Fatal Schema (`Breaks during next rule addition`):**
```python
assert len(get_all_rules()) == 272
```
