# Adding Rules

SlowQL evaluates SQL logic through isolated `Rule` modules. The engine architecture partitions rules by physical dimension to streamline debugging and documentation boundaries.

```text
src/slowql/rules/
├── security/       # Injection, Exfiltration
├── performance/    # IO Scaling, Missing Indicies
├── reliability/    # Unbounded Deletes, Transactions
├── cost/           # Cartesian Joins, Network Egress
├── compliance/     # PCI-DSS, GDPR
└── quality/        # Style drift, Deprecated Syntax
```

## System Interfaces

Every rule inside the engine extends fundamentally from one of two parent classes depending on execution necessity:

### 1. PatternRule
Used for string-matching payloads. Inherit `PatternRule` exclusively when an immutable Regex string resolves the vulnerability faster than full AST parsing.

```python
from slowql.rules.base import PatternRule
from slowql.core.models import Severity, Dimension

class NakedDeleteRule(PatternRule):
    id = "REL-DATA-001"
    name = "Unbounded Delete Detection"
    severity = Severity.CRITICAL
    dimension = Dimension.RELIABILITY
    
    # Empty tuple enforces universality across all dialects
    dialects = () 

    pattern = r"(?i)^\s*DELETE\s+FROM\s+\w+\s*(?!WHERE|RETURNING|;)"
    impact = "An unqualified DELETE will purge the entire target architecture."
    fix_guidance = "Append an explicit WHERE clause or switch to TRUNCATE."
```

### 2. ASTRule
Used for mathematical traversal of the SQL syntax structure. Inherit from `ASTRule` to loop over parsed `sqlglot` nodes.

```python
from sqlglot import exp
from slowql.rules.base import ASTRule
from slowql.core.models import Query, Issue, Location

class SelectAsteriskRule(ASTRule):
    id = "PERF-SCAN-001"
    
    def check_ast(self, query: Query, ast: exp.Expression) -> list[Issue]:
        issues = []
        for star in ast.find_all(exp.Star):
            # Complex parent traversal checking if the Star is buried
            parent = star.parent
            if isinstance(parent, exp.Select):
                issues.append(
                    Issue(
                        rule_id=self.id,
                        message="Wildcard projection detected.",
                        location=Location(
                            line=query.location.line, 
                            column=query.location.column
                        )
                    )
                )
        return issues
```

## Dialect Guarding

Not all vulnerabilities span dynamically across database providers. To restrict a rule's execution entirely to an explicit datastore logic:

```python
class SnowflakeOptimizationRule(ASTRule):
    id = "COST-SF-001"
    
    # The rule engine mathematically guarantees this object will only 
    # execute if the active document is parsed natively as Snowflake.
    dialects = ("snowflake",)
```

## Remediation Autofixing

SlowQL engineers its `--fix` capabilities natively through returning `Fix` class artifacts. 
To construct an automated repair sequence, assign `RemediationMode.SAFE_APPLY` class attributes and construct a 100% semantically equivalent replacement.

```python
from slowql.core.models import Fix, RemediationMode, FixConfidence
import re

class DeprecatedJoinRule(PatternRule):
    id = "QUAL-MODERN-001"
    remediation_mode = RemediationMode.SAFE_APPLY

    def suggest_fix(self, query: Query) -> Fix | None:
        match = re.search(r"(\w+),\s*(\w+)", query.raw, re.IGNORECASE)
        if not match:
            return None
            
        return Fix(
            description="Replaced Comma Join natively with CROSS JOIN",
            original=match.group(0),
            replacement=f"{match.group(1)} CROSS JOIN {match.group(2)}",
            confidence=FixConfidence.SAFE,
            is_safe=True,
            rule_id=self.id,
        )
```

## Final Registry Process

Once the class is validated:
1. Embed the newly manufactured class into the native file's `__all__` list.
2. Initialize the class explicitly inside `src/slowql/rules/catalog.py` under the `get_all_rules()` function so the Master Registry incorporates its AST schema map.
