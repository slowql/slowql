"""
Performance Memory rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    "GroupByHighCardinalityRule",
    "LargeInClauseRule",
    "OrderByWithoutLimitInSubqueryRule",
    "UnboundedTempTableRule",
]


class LargeInClauseRule(ASTRule):
    """Detects IN clauses with excessive values (>50)."""

    id = "PERF-MEM-001"
    name = "Large IN Clause"
    description = "Detects IN clauses with excessive values (>50) that can cause memory pressure and poor plans."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.In):
                values = getattr(node, "expressions", [])
                if not values and getattr(node, "query", None):
                    continue  # Subquery, not literal list

                if len(values) > 50:
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"IN clause with {len(values)} values - consider using temp table or table-valued parameter",
                            snippet=str(node)[:100],
                            impact=(
                                "Large IN clauses (100+ values) consume memory for query compilation, bloat the plan cache "
                                "with unique plans, and may force suboptimal execution strategies."
                            ),
                            fix=Fix(
                                description="Load values into a temp table or table-valued parameter (TVP), then JOIN.",
                                replacement="",
                                is_safe=False,
                            ),
                        )
                    )

        return issues


class UnboundedTempTableRule(PatternRule):
    """Detects SELECT INTO temp table without WHERE clause or row limit."""

    id = "PERF-MEM-002"
    name = "Unbounded Temp Table Creation"
    description = "Detects SELECT INTO temp table without WHERE clause or row limit."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY
    dialects = ("tsql",)

    pattern = r"\bSELECT\b(?!.*\b(WHERE|TOP|LIMIT)\b)[^;]*\bINTO\s+[#@\w]+"
    message_template = "Unbounded SELECT INTO temp table detected: {match}"

    impact = (
        "Unbounded SELECT INTO can fill tempdb, crash the instance, or exhaust memory. "
        "A single runaway query can impact all database users."
    )
    fix_guidance = "Always add WHERE clause or TOP/LIMIT to bound result size. Pre-create temp table with explicit schema for better memory estimation."


class OrderByWithoutLimitInSubqueryRule(ASTRule):
    """Detects ORDER BY in subqueries without LIMIT."""

    id = "PERF-MEM-003"
    name = "ORDER BY Without LIMIT in Subquery"
    description = "Detects ORDER BY in subqueries/CTEs without TOP/LIMIT, which is meaningless and wastes resources."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Subquery):
                inner = node.this
                if isinstance(inner, exp.Select):
                    has_order = inner.args.get("order") is not None
                    has_limit = inner.args.get("limit") is not None

                    if has_order and not has_limit:
                        issues.append(
                            self.create_issue(
                                query=query,
                                message="ORDER BY in subquery without LIMIT is meaningless and wastes resources",
                                snippet=str(inner)[:100],
                                impact=(
                                    "Sorting requires memory allocation and CPU. ORDER BY without LIMIT in subqueries "
                                    "does nothing (SQL standard ignores it) but still consumes resources."
                                ),
                                fix=Fix(
                                    description="Remove ORDER BY from subqueries unless paired with TOP/LIMIT. Apply ordering in the final outer query only.",
                                    replacement="",
                                    is_safe=False,
                                ),
                            )
                        )

        return issues


class GroupByHighCardinalityRule(ASTRule):
    """Detects GROUP BY on columns likely to have high cardinality (timestamps, IDs, UUIDs)."""

    id = "PERF-MEM-004"
    name = "GROUP BY on High-Cardinality Expression"
    description = (
        "Detects GROUP BY on columns likely to have high cardinality (timestamps, IDs, UUIDs)."
    )
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        high_cardinality_patterns = {
            "timestamp",
            "datetime",
            "created_at",
            "updated_at",
            "modified_at",
            "uuid",
            "guid",
            "id",
            "transaction_id",
            "session_id",
            "request_id",
            "email",
            "phone",
            "ip_address",
            "user_agent",
        }

        for node in ast.walk():
            if isinstance(node, exp.Select):
                group = node.args.get("group")
                if group:
                    expressions = getattr(group, "expressions", [group])
                    for expr in expressions:
                        if isinstance(expr, exp.Column):
                            col_name = getattr(expr, "name", "").lower()
                            if any(hc in col_name for hc in high_cardinality_patterns):
                                issues.append(
                                    self.create_issue(
                                        query=query,
                                        message=f"GROUP BY on high-cardinality column '{expr.name}' - may create excessive groups",
                                        snippet=str(node)[:100],
                                        impact=(
                                            "Grouping by high-cardinality columns (timestamps, UUIDs) creates millions of groups, "
                                            "consuming massive memory and producing unusable results."
                                        ),
                                        fix=Fix(
                                            description="Truncate timestamps to meaningful intervals (e.g., DATE_TRUNC). Group by categorical columns.",
                                            replacement="",
                                            is_safe=False,
                                        ),
                                    )
                                )

        return issues
