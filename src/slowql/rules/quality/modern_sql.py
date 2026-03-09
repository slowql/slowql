"""
Quality Modern sql rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'HardcodedDateRule',
    'ImplicitJoinRule',
    'UnionWithoutAllRule',
]


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

    pattern = (
        r"\bWHERE\b.+['\"](\d{4}-\d{2}-\d{2})['\"]"
    )
    message_template = "Hardcoded date literal detected in WHERE clause — consider using parameters: {match}"

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
    message_template = "UNION without ALL detected — use UNION ALL if duplicates are not a concern: {match}"

    impact = (
        "UNION deduplicates results using an expensive sort or hash operation. "
        "On large result sets this adds significant overhead compared to UNION ALL."
    )
    fix_guidance = (
        "If the result sets cannot contain meaningful duplicates, replace UNION "
        "with UNION ALL. If deduplication is required, keep UNION and add a "
        "comment explaining why to prevent future 'optimization' regressions."
    )
