from __future__ import annotations

"""
Performance Aggregation rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'OrderByInSubqueryRule',
    'UnfilteredAggregationRule',
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
