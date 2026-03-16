"""
Performance Aggregation rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    "HavingWithoutGroupByRule",
    "OrderByInSubqueryRule",
    "UnfilteredAggregationRule",
]


class UnfilteredAggregationRule(ASTRule):
    """Detects aggregation without a WHERE clause."""

    id = "PERF-AGG-001"
    name = "Unfiltered Aggregation"
    description = "Detects COUNT(*), SUM(), AVG() without a WHERE clause on SELECT."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_AGGREGATION

    impact = "Aggregates entire table, expensive on large datasets"
    fix_guidance = "Add WHERE clause to filter rows before aggregation"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if not query.is_select:
            return []

        has_agg = bool(
            list(ast.find_all(exp.Count))
            or list(ast.find_all(exp.Sum))
            or list(ast.find_all(exp.Avg))
        )

        if has_agg and not ast.find(exp.Where):
            return [
                self.create_issue(
                    query=query,
                    message="Aggregation without WHERE clause scans entire table.",
                    snippet=query.raw[:80],
                )
            ]
        return []


class OrderByInSubqueryRule(PatternRule):
    """Detects ORDER BY inside a subquery or CTE."""

    id = "PERF-AGG-002"
    name = "ORDER BY in Subquery"
    description = "Detects ORDER BY inside a subquery or CTE where it is typically meaningless."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_AGGREGATION

    pattern = r"\(\s*SELECT\b[^)]+\bORDER\s+BY\b"
    message_template = "ORDER BY in subquery is typically meaningless: {match}"

    impact = "ORDER BY in subquery is meaningless and wastes sort cost"
    fix_guidance = "Remove ORDER BY from subquery unless paired with LIMIT/TOP"


class HavingWithoutGroupByRule(ASTRule):
    """Detects HAVING clause without GROUP BY."""

    id = "PERF-AGG-003"
    name = "HAVING Without GROUP BY"
    description = (
        "HAVING without GROUP BY treats the entire result set as a single "
        "group. This is valid SQL but almost always a mistake — the developer "
        "likely forgot GROUP BY, and the query returns at most one row."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_AGGREGATION
    dialects = ()

    impact = (
        "Without GROUP BY, HAVING filters the entire table as one group. "
        "The query returns either 0 or 1 rows, which is rarely intended."
    )
    fix_guidance = (
        "Add the missing GROUP BY clause, or use WHERE instead of HAVING "
        "if no aggregation is needed."
    )

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                having = node.args.get("having")
                group = node.args.get("group")
                if having and not group:
                    issues.append(self.create_issue(
                        query=query,
                        message="HAVING without GROUP BY — entire result treated as single group.",
                        snippet=query.raw[:80],
                    ))
        return issues
