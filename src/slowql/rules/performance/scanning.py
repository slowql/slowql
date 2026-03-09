from __future__ import annotations

"""
Performance Scanning rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'DistinctOnLargeSetRule',
    'MissingWhereRule',
    'NotInSubqueryRule',
    'SelectStarRule',
    'UnboundedSelectRule',
]


class SelectStarRule(ASTRule):
    """Detects usage of SELECT *."""

    id = "PERF-SCAN-001"
    name = "SELECT * Usage"
    description = "Detects wildcard selection (SELECT *) which causes unnecessary I/O."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        if query.is_select:
            # Check for star in projections
            for expression in ast.find_all(exp.Star):
                # Ensure it's in the projection list (not count(*))
                parent = expression.parent
                if isinstance(parent, exp.Select):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="Avoid 'SELECT *'. Explicitly list required columns.",
                            snippet="SELECT *",
                            fix=Fix(
                                description="Replace * with specific column names",
                                replacement="SELECT col1, col2 ...",  # Placeholder logic
                                is_safe=False,  # Cannot safely auto-fix without schema
                            ),
                            impact="Increases network traffic, memory usage, and prevents covering "
                            "index usage.",
                        )
                    )
                    break  # Report once per query
        return issues


class MissingWhereRule(ASTRule):
    """Detects UPDATE/DELETE without WHERE (Performance aspect)."""

    # Note: This is also a Reliability rule, but handled here for large scan prevention

    id = "PERF-SCAN-002"
    name = "Unbounded Data Modification"
    description = "Detects UPDATE/DELETE statements affecting all rows."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if query.query_type not in ("UPDATE", "DELETE"):
            return []

        # Check for WHERE clause
        if not ast.find(exp.Where):
            return [
                self.create_issue(
                    query=query,
                    message=f"Unbounded {query.query_type} detected (missing WHERE).",
                    snippet=query.raw[:50],
                    impact="Will modify/delete ALL rows in the table, causing massive lock "
                    "contention and log growth.",
                )
            ]

        return []


class DistinctOnLargeSetRule(ASTRule):
    """Detects DISTINCT usage which causes sorting overhead."""

    id = "PERF-SCAN-005"
    name = "Expensive DISTINCT"
    description = "Detects DISTINCT usage which triggers expensive sort/hash operations."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if isinstance(ast, exp.Select) and ast.args.get("distinct"):
            return [
                self.create_issue(
                    query=query,
                    message="DISTINCT usage detected. Ensure this is necessary.",
                    snippet="SELECT DISTINCT ...",
                    impact="Requires sorting or hashing entire result set. Check if data model "
                    "allows duplicates.",
                )
            ]
        return []


class UnboundedSelectRule(ASTRule):
    """Detects SELECT without LIMIT on non-aggregated queries."""

    id = "PERF-SCAN-003"
    name = "Unbounded SELECT"
    description = "Detects SELECT statements with no LIMIT clause on non-aggregated queries."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    impact = "May return millions of rows, overwhelming application memory"
    fix_guidance = "Add LIMIT clause for paginated or exploratory queries"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if not query.is_select:
            return []

        has_group_by = ast.find(exp.Group) is not None
        has_limit = ast.find(exp.Limit) is not None
        has_agg = bool(
            list(ast.find_all(exp.Count))
            or list(ast.find_all(exp.Sum))
            or list(ast.find_all(exp.Avg))
        )

        if not has_group_by and not has_limit and not has_agg:
            return [
                self.create_issue(
                    query=query,
                    message="SELECT without LIMIT on non-aggregated query.",
                    snippet=query.raw[:80],
                )
            ]
        return []


class NotInSubqueryRule(ASTRule):
    """Detects NOT IN (...subquery...) pattern."""

    id = "PERF-SCAN-004"
    name = "NOT IN Subquery"
    description = "Detects NOT IN with subquery which can fail silently with NULLs."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    impact = "NOT IN with subquery fails silently with NULLs and disables index usage"
    fix_guidance = "Rewrite as NOT EXISTS or LEFT JOIN ... WHERE col IS NULL"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for not_node in ast.find_all(exp.Not):
            in_node = not_node.find(exp.In)
            if in_node is not None:
                # Check if the IN contains a subquery
                if in_node.find(exp.Select):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="NOT IN with subquery detected. Vulnerable to NULL semantics.",
                            snippet=str(not_node),
                        )
                    )
                    break  # Report once per query
        return issues
