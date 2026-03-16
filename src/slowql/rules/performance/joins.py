"""
Performance Joins rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule

__all__ = [
    "CartesianProductRule",
    "LeftJoinWithIsNotNullRule",
    "TooManyJoinsRule",
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


class LeftJoinWithIsNotNullRule(ASTRule):
    """Detects LEFT JOIN where WHERE filters on right table IS NOT NULL."""

    id = "PERF-JOIN-003"
    name = "LEFT JOIN With IS NOT NULL Filter"
    description = (
        "A LEFT JOIN followed by WHERE right_table.column IS NOT NULL is "
        "logically equivalent to an INNER JOIN but prevents the optimizer "
        "from choosing the most efficient join strategy."
    )
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_JOIN
    dialects = ()

    impact = (
        "The LEFT JOIN preserves unmatched rows, then WHERE immediately "
        "removes them. This wastes I/O and prevents join reordering."
    )
    fix_guidance = (
        "Replace LEFT JOIN with INNER JOIN when the WHERE clause filters "
        "out NULLs from the right table. The result is identical but "
        "the optimizer has more freedom."
    )

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                joins = node.args.get("joins") or []
                where = node.args.get("where")
                if not where:
                    continue

                # Get right-side table names from LEFT JOINs
                left_join_tables = set()
                for join in joins:
                    join_kind = join.args.get("side", "")
                    if str(join_kind).upper() == "LEFT":
                        table = join.find(exp.Table)
                        if table:
                            left_join_tables.add(table.alias_or_name.lower())

                if not left_join_tables:
                    continue

                # Check WHERE for IS NOT NULL on left-joined table columns
                where_sql = str(where).upper()
                for table_name in left_join_tables:
                    if f"{table_name.upper()}." in where_sql and "IS NOT NULL" in where_sql:
                        issues.append(self.create_issue(
                            query=query,
                            message=f"LEFT JOIN on '{table_name}' with IS NOT NULL filter — use INNER JOIN instead.",
                            snippet=query.raw[:80],
                        ))
                        break
        return issues
