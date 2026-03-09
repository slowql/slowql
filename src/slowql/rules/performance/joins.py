"""
Performance Joins rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule

__all__ = [
    'CartesianProductRule',
    'TooManyJoinsRule',
]


class CartesianProductRule(ASTRule):
    """Detects CROSS JOIN usage."""

    id = "PERF-JOIN-001"
    name = "Cartesian Product (CROSS JOIN)"
    description = "Detects CROSS JOIN usage which produces a Cartesian product of rows."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_JOIN

    impact = "Produces row count = table1_rows * table2_rows, exponential cost"
    fix_guidance = "Add explicit JOIN condition or use INNER JOIN"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for join in ast.find_all(exp.Join):
            kind = join.args.get("kind")
            if kind and str(kind).upper() == "CROSS":
                issues.append(
                    self.create_issue(
                        query=query,
                        message="CROSS JOIN detected. This produces a Cartesian product.",
                        snippet=str(join),
                    )
                )
                break  # Report once per query
        return issues


class TooManyJoinsRule(ASTRule):
    """Detects queries with 5 or more JOINs."""

    id = "PERF-JOIN-002"
    name = "Excessive Joins"
    description = "Detects queries with 5 or more JOIN clauses."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_JOIN

    impact = "High join count increases query plan complexity and memory usage"
    fix_guidance = "Consider breaking into CTEs or denormalizing hot query paths"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        joins = list(ast.find_all(exp.Join))
        if len(joins) >= 5:
            return [
                self.create_issue(
                    query=query,
                    message=f"Query has {len(joins)} JOINs. Consider simplifying.",
                    snippet=query.raw[:80],
                )
            ]
        return []
