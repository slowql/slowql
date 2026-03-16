"""
Quality Modern sql rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    "HardcodedDateRule",
    "ImplicitJoinRule",
    "OracleNvlInWhereRule",
    "RownumWithoutOrderByRule",
    "SelectFromDualRule",
    "SqlCalcFoundRowsRule",
    "UnionWithoutAllRule",
]


class RownumWithoutOrderByRule(PatternRule):
    """Detects ROWNUM without ORDER BY."""

    id = "QUAL-ORA-001"
    name = "ROWNUM Without ORDER BY"
    dialects = ("oracle",)
    severity = Severity.HIGH
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    pattern = r"\bROWNUM\b(?![\s\S]*\bORDER\s+BY\b)"
    message_template = (
        "ROWNUM used without ORDER BY — row selection is non-deterministic: {match}"
    )
    impact = (
        "ROWNUM filters rows BEFORE ORDER BY is applied. "
        "SELECT * FROM t WHERE ROWNUM <= 10 ORDER BY date returns 10 arbitrary rows then sorts them — "
        "not the top 10 by date. Results are non-deterministic and change with optimizer plan."
    )
    fix_guidance = (
        "Wrap in a subquery: SELECT * FROM (SELECT * FROM t ORDER BY date) WHERE ROWNUM <= 10. "
        "Or use the modern FETCH FIRST syntax: SELECT * FROM t ORDER BY date FETCH FIRST 10 ROWS ONLY."
    )


class SelectFromDualRule(PatternRule):
    """Detects SELECT FROM DUAL in Application SQL."""

    id = "QUAL-ORA-002"
    name = "SELECT FROM DUAL in Application SQL"
    dialects = ("oracle",)
    severity = Severity.INFO
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    pattern = r"\bFROM\s+DUAL\b"
    message_template = "SELECT FROM DUAL detected — consider using modern syntax: {match}"
    impact = (
        "SELECT 1 FROM DUAL is Oracle-specific legacy syntax for selecting constants. "
        "It works but is non-portable and signals Oracle-specific code that cannot "
        "be migrated to PostgreSQL, MySQL, or other databases without modification."
    )
    fix_guidance = (
        "Use SELECT 1 (no FROM clause) which works in most modern databases. "
        "Oracle 23c+ supports SELECT 1 without FROM DUAL."
    )


class ImplicitJoinRule(ASTRule):
    """Detects implicit joins (comma-separated tables)."""

    id = "QUAL-MODERN-001"
    name = "Implicit Join Syntax"
    description = "Detects old-style implicit joins using commas in FROM clause."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if not query.is_select:
            return []

        # Check if FROM has multiple tables in the same From node (comma separation)
        from_clause = ast.find(exp.From)
        if from_clause and len(from_clause.expressions) > 1:
            return [
                self.create_issue(
                    query=query,
                    message="Implicit join syntax detected (comma-separated tables).",
                    snippet=str(from_clause),
                    fix=Fix(
                        description="Convert to explicit INNER JOIN",
                        replacement="... FROM table1 JOIN table2 ON ...",
                        is_safe=False,
                    ),
                    impact="Implicit joins are harder to read and prone to accidental cross-joins.",
                )
            ]
        return []


class HardcodedDateRule(PatternRule):
    """Detects hardcoded date literals in WHERE clauses."""

    id = "QUAL-MODERN-002"
    name = "Hardcoded Date Literal in Filter"
    description = (
        "Detects hardcoded date strings in WHERE clauses (e.g., WHERE date = '2023-01-01'). "
        "Hardcoded dates create maintenance burden, break time-based logic silently "
        "as time passes, and are a common source of stale query bugs."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN

    pattern = r"\bWHERE\b.+['\"](\d{4}-\d{2}-\d{2})['\"]"
    message_template = (
        "Hardcoded date literal detected in WHERE clause — consider using parameters: {match}"
    )

    impact = (
        "Hardcoded dates become stale and cause queries to return unexpected "
        "results or no results as time passes. They also prevent query plan reuse."
    )
    fix_guidance = (
        "Replace hardcoded dates with parameterized values (?), bind variables "
        "(:date), or dynamic expressions like NOW(), CURRENT_DATE, or "
        "CURRENT_DATE - INTERVAL '30 days'."
    )


class UnionWithoutAllRule(PatternRule):
    """Detects UNION without ALL where UNION ALL is likely intended for performance."""

    id = "QUAL-MODERN-003"
    name = "UNION Without ALL — Implicit Deduplication"
    description = (
        "Detects UNION without ALL. UNION performs an implicit DISTINCT which "
        "requires a sort or hash operation over the full result set. If duplicate "
        "elimination is not required, UNION ALL is significantly faster."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN

    pattern = r"\bUNION\b(?!\s+ALL\b)"
    message_template = (
        "UNION without ALL detected — use UNION ALL if duplicates are not a concern: {match}"
    )

    impact = (
        "UNION deduplicates results using an expensive sort or hash operation. "
        "On large result sets this adds significant overhead compared to UNION ALL."
    )
    fix_guidance = (
        "If the result sets cannot contain meaningful duplicates, replace UNION "
        "with UNION ALL. If deduplication is required, keep UNION and add a "
        "comment explaining why to prevent future 'optimization' regressions."
    )


class SqlCalcFoundRowsRule(PatternRule):
    """Detects deprecated SQL_CALC_FOUND_ROWS usage in MySQL."""

    id = "QUAL-MYSQL-001"
    name = "Deprecated SQL_CALC_FOUND_ROWS"
    description = (
        "SQL_CALC_FOUND_ROWS is deprecated as of MySQL 8.0.17. It forces the "
        "server to compute the full result set size even when LIMIT is used, "
        "causing unnecessary overhead."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN
    dialects = ("mysql",)

    pattern = r"\bSQL_CALC_FOUND_ROWS\b"
    message_template = "Deprecated SQL_CALC_FOUND_ROWS usage: {match}"

    impact = (
        "SQL_CALC_FOUND_ROWS disables LIMIT optimisations and forces a full "
        "table scan to count all matching rows. It is deprecated and will be "
        "removed in a future MySQL version."
    )
    fix_guidance = (
        "Replace with two separate queries: one with LIMIT for the page and "
        "one COUNT(*) query for the total. Use covering indexes to make the "
        "COUNT(*) query fast."
    )


class OracleNvlInWhereRule(PatternRule):
    """Detects NVL() in WHERE clause instead of IS NULL in Oracle."""

    id = "QUAL-ORA-003"
    name = "NVL in WHERE Clause"
    description = "NVL() in WHERE wraps the column in a function, preventing index usage."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN
    dialects = ("oracle",)
    pattern = r"\bWHERE\b.*\bNVL\s*\("
    message_template = "NVL() in WHERE clause — prevents index usage: {match}"
    impact = "NVL() makes the predicate non-SARGable."
    fix_guidance = "Replace NVL(col, val) = x with (col = x OR col IS NULL)."
