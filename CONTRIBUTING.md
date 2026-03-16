# Contributing to SlowQL

Thank you for your interest in contributing to SlowQL. This document covers setup, workflow, and guidelines for adding rules, autofixes, and dialect support.

## Setup

```bash
git clone https://github.com/makroumi/slowql.git
cd slowql
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify everything works:

```bash
pytest
ruff check .
mypy src/slowql
```

## Development Workflow

1. Fork the repository.
2. Create a feature branch from `main`:
```bash
git checkout -b feat/my-feature
```
3. Write tests before or alongside your code.
4. Run the full check suite before pushing:
```bash
ruff check .
mypy src/slowql
pytest
```
5. Open a pull request against `main`.

## Code Style

**Formatting.** Handled by `ruff format`. Run `ruff format .` before committing.

**Linting.** `ruff check .` must pass with zero errors.

**Type hints.** Required on all functions and methods. Checked via `mypy --strict`.

**Line length.** 100 characters.

**Imports.** Sorted by `ruff`. Use `from __future__ import annotations` in every file.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add PERF-PG-005 rule for unlogged table detection
fix: correct dialect matching for postgres alias
docs: update README rule counts
test: add autofix end-to-end tests
chore: bump sqlglot dependency
```

## Pull Requests

Include a clear description of what changed and why. Reference related issues with `Closes #123`. Ensure CI passes before requesting review. One logical change per PR.

## Adding Rules

SlowQL has 272 rules across six dimensions. Rules live in `src/slowql/rules/` organized by dimension:

```
src/slowql/rules/
├── security/       # SEC-* rules
├── performance/    # PERF-* rules
├── reliability/    # REL-* rules
├── cost/           # COST-* rules
├── compliance/     # COMP-* rules
└── quality/        # QUAL-* rules
```

Each dimension can have dialect-specific files (e.g., `performance/redshift.py`, `security/sqlite.py`) or shared files (e.g., `performance/scanning.py` for universal rules).

### Rule Types

**PatternRule.** Regex-based detection. Simplest to write. Use when a regex can reliably identify the issue.

```python
class MyRule(PatternRule):
    id = "SEC-EXAMPLE-001"
    name = "Example Pattern Rule"
    description = "Detects something bad."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION
    dialects = ("postgresql",)  # omit for universal rules

    pattern = r"\bBAD_PATTERN\b"
    message_template = "Bad pattern found: {match}"
    impact = "What happens if this is not fixed."
    fix_guidance = "How to fix it."
```

**ASTRule.** Uses sqlglot AST traversal. Use when you need to inspect query structure (joins, where clauses, subqueries).

```python
class MyASTRule(ASTRule):
    id = "PERF-EXAMPLE-001"
    name = "Example AST Rule"
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ()  # universal

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                # detection logic
                pass
        return issues
```

**Custom Rule.** Subclass `Rule` directly when you need logic that combines regex and AST or has complex conditions. You must call `self._dialect_matches(query)` as the first check in `check()`.

```python
class MyCustomRule(Rule):
    id = "REL-EXAMPLE-001"
    name = "Example Custom Rule"
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    dialects = ("tsql",)

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        # custom logic here
        return []
```

### Dialect-Specific Rules

If your rule only applies to a specific database engine, set the `dialects` attribute:

```python
dialects = ("postgresql",)           # single dialect
dialects = ("presto", "trino")       # multiple dialects
dialects = ()                        # universal (all dialects)
```

Use canonical dialect names: `postgresql`, `mysql`, `tsql`, `oracle`, `sqlite`, `snowflake`, `bigquery`, `redshift`, `clickhouse`, `duckdb`, `presto`, `trino`, `spark`, `databricks`.

Common aliases (`postgres`, `mssql`, `pg`, `bq`, `sf`) are normalized automatically by `slowql.core.dialects.normalize_dialect()`.

### Checklist for New Rules

1. Create the rule class in the appropriate file under `src/slowql/rules/<dimension>/`.
2. Add the class name to the file's `__all__` list.
3. Add the class name to the dimension's `__init__.py` `__all__` list (if using `from .module import *`).
4. Import and instantiate the rule in `src/slowql/rules/catalog.py` inside `get_all_rules()`.
5. Write tests. At minimum:
   - Test that the rule fires on a matching query with the correct dialect.
   - Test that the rule does NOT fire on a non-matching query.
   - Test that the rule skips queries with a different dialect (for dialect-specific rules).
6. Include `impact` and `fix_guidance` on every rule.
7. Run `ruff check .`, `mypy src/slowql`, and `pytest` before submitting.

### Rule ID Convention

```
{DIMENSION}-{SUBCATEGORY}-{NUMBER}

SEC-INJ-001       # Security > Injection > rule 1
PERF-PG-002       # Performance > PostgreSQL-specific > rule 2
REL-TSQL-003      # Reliability > T-SQL-specific > rule 3
COST-BQ-001       # Cost > BigQuery-specific > rule 1
QUAL-MODERN-004   # Quality > Modern SQL > rule 4
COMP-GDPR-001     # Compliance > GDPR > rule 1
```

Dialect-specific rules use the dialect abbreviation as the subcategory: `PG`, `MYSQL`, `TSQL`, `ORA`, `SF`, `BQ`, `SQLITE`, `RS`, `CH`, `DUCK`, `PRESTO`, `SPARK`.

## Adding Safe Autofixes

Autofixes are implemented via `suggest_fix()` on the rule class. Only add autofixes where the replacement is **100% semantically equivalent** to the original.

```python
class MyRule(PatternRule):
    id = "QUAL-EXAMPLE-001"
    remediation_mode = RemediationMode.SAFE_APPLY

    def suggest_fix(self, query: Query) -> Fix | None:
        match = re.search(r"\bOLD_SYNTAX\b", query.raw, re.IGNORECASE)
        if not match:
            return None
        return Fix(
            description="Replace OLD_SYNTAX with NEW_SYNTAX",
            original=match.group(0),
            replacement="NEW_SYNTAX",
            confidence=FixConfidence.SAFE,
            is_safe=True,
            rule_id=self.id,
        )
```

Autofix requirements:

1. The fix must produce SQL that is functionally identical to the input. If there is any ambiguity, do not add an autofix.
2. Set `confidence=FixConfidence.SAFE` and `is_safe=True`.
3. Set `remediation_mode = RemediationMode.SAFE_APPLY` on the rule class.
4. Test that `AutoFixer().apply_fix(sql, fix)` produces the expected output.
5. Test that `AutoFixer().preview_fixes(sql, [fix])` produces a valid unified diff.

## Testing

Tests live in `tests/`. Rule tests can go in dedicated test files (e.g., `tests/test_dialect_rules_phase3.py`) or in `tests/unit/test_rules.py`.

Minimal test helper:

```python
from slowql.core.models import Location, Query

_LOC = Location(line=1, column=1)

def _q(sql: str, dialect: str, query_type: str = "SELECT") -> Query:
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type=query_type)
```

For AST-based rules, parse the SQL first:

```python
import sqlglot

def _q(sql: str, dialect: str) -> Query:
    try:
        ast = sqlglot.parse_one(sql)
    except Exception:
        ast = None
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type="SELECT", ast=ast)
```

Do not hardcode total rule counts in assertions. Use `>=` thresholds:

```python
# Good
assert len(get_all_rules()) >= 270

# Bad — breaks every time a rule is added
assert len(get_all_rules()) == 272
```

## Project Structure

```
src/slowql/
├── core/           # Engine, config, models, exceptions, autofixer, dialects
├── cli/            # CLI entry point and TUI (Rich-based)
├── parser/         # SQL parsing (sqlglot), tokenizer, source splitter
├── analyzers/      # Six dimension analyzers + registry
├── rules/          # 272 detection rules organized by dimension
│   ├── base.py     # Rule, PatternRule, ASTRule base classes
│   ├── catalog.py  # Central rule registry (get_all_rules)
│   ├── registry.py # RuleRegistry class
│   └── schema/     # Schema-aware validation rules
├── schema/         # DDL parser, schema models, inspector
├── reporters/      # Console, JSON, HTML, CSV, SARIF, GitHub Actions
├── lsp/            # Language Server Protocol support
└── utils/          # I/O and text utilities
```

## Questions

Open an issue or start a discussion at [github.com/makroumi/slowql/discussions](https://github.com/makroumi/slowql/discussions).