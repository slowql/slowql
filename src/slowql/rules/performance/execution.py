"""
Performance Execution rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    "CorrelatedSubqueryRule",
    "OrderByNonIndexedColumnRule",
    "ScalarUdfInQueryRule",
]


class ScalarUdfInQueryRule(PatternRule):
    """Detects scalar user-defined function calls in SELECT or WHERE clauses."""

    id = "PERF-SCALAR-001"
    name = "Scalar UDF in SELECT/WHERE"
    description = "Detects scalar user-defined function calls in SELECT or WHERE clauses."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_EXECUTION
    dialects = ("tsql",)

    pattern = r"\b(SELECT|WHERE)\b[^;]*\bdbo\.\w+\s*\([^)]*\)"
    message_template = "Scalar UDF detected: {match}"

    impact = (
        "Scalar UDFs execute row-by-row, prevent parallelism, and cannot be inlined in most SQL versions. "
        "A single scalar UDF can make queries 100x slower."
    )
    fix_guidance = (
        "Rewrite as inline table-valued function (iTVF) or move logic to application layer."
    )


class CorrelatedSubqueryRule(ASTRule):
    """Detects correlated subqueries that execute once per outer row."""

    id = "PERF-SCALAR-002"
    name = "Correlated Subquery"
    description = "Detects correlated subqueries that execute once per outer row."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_EXECUTION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Select):
                for subq in node.find_all(exp.Subquery):
                    inner = subq.this
                    if isinstance(inner, exp.Select):
                        outer_tables = self._get_table_aliases(node)
                        inner_refs = self._get_column_table_refs(inner)

                        if outer_tables and inner_refs and (outer_tables & inner_refs):
                            issues.append(
                                self.create_issue(
                                    query=query,
                                    message="Correlated subquery executes once per outer row - consider rewriting as JOIN",
                                    snippet=str(subq)[:100],
                                    impact=(
                                        "Correlated subqueries execute for every row in the outer query. "
                                        "For 1 million outer rows, the subquery runs 1 million times."
                                    ),
                                    fix=Fix(
                                        description="Rewrite as JOIN or use window functions.",
                                        replacement="",
                                        is_safe=False,
                                    ),
                                )
                            )

        return issues

    def _get_table_aliases(self, node: Any) -> set[str]:
        aliases = set()
        for table in node.find_all(exp.Table):
            if table.alias:
                aliases.add(table.alias.lower())
            elif getattr(table, "name", None):
                aliases.add(getattr(table, "name", "").lower())
        return aliases

    def _get_column_table_refs(self, node: Any) -> set[str]:
        refs = set()
        for col in node.find_all(exp.Column):
            if col.table:
                refs.add(col.table.lower())
        return refs


class OrderByNonIndexedColumnRule(ASTRule):
    """Detects ORDER BY on columns unlikely to be indexed."""

    id = "PERF-SORT-001"
    name = "ORDER BY on Non-Indexed Column"
    description = "Detects ORDER BY on columns unlikely to be indexed, forcing expensive sorts."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SORT

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        unlikely_indexed = {
            "description",
            "notes",
            "comments",
            "body",
            "content",
            "message",
            "address",
            "bio",
            "about",
            "metadata",
            "json_data",
            "xml_data",
            "calculated",
            "computed",
            "derived",
        }

        for node in ast.walk():
            if isinstance(node, exp.Select):
                order = node.args.get("order")
                if order:
                    expressions = getattr(order, "expressions", [order])
                    for expr in expressions:
                        if isinstance(expr, exp.Ordered):
                            col = expr.this
                            if isinstance(col, exp.Column):
                                col_name = getattr(col, "name", "").lower()
                                if any(ui in col_name for ui in unlikely_indexed):
                                    issues.append(
                                        self.create_issue(
                                            query=query,
                                            message=f"ORDER BY on likely non-indexed column '{col.name}' - may require expensive sort",
                                            snippet=str(node)[:100],
                                            impact=(
                                                "Sorting without index support requires loading all rows into memory, sorting, then returning. "
                                                "For large tables, this spills to disk (tempdb), dramatically slowing queries."
                                            ),
                                            fix=Fix(
                                                description="Create covering index including ORDER BY columns. Or add index on frequently sorted columns.",
                                                replacement="",
                                                is_safe=False,
                                            ),
                                        )
                                    )

        return issues
