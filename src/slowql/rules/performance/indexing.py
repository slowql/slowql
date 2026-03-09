from __future__ import annotations

"""
Performance Indexing rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'CoalesceOnIndexedColumnRule',
    'CompositeIndexOrderViolationRule',
    'DeepOffsetPaginationRule',
    'FunctionOnIndexedColumnRule',
    'ImplicitTypeConversionRule',
    'LeadingWildcardRule',
    'NegationOnIndexedColumnRule',
    'NonSargableOrConditionRule',
    'OrOnIndexedColumnsRule',
]


class LeadingWildcardRule(PatternRule):
    """Detects leading wildcards in LIKE clauses."""

    id = "PERF-IDX-002"
    name = "Leading Wildcard Search"
    description = "Detects LIKE '%value' patterns which prevent index usage."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    pattern = r"\s+LIKE\s+['\"]%[^'\"]+['\"]"
    message_template = "Non-SARGable query: Leading wildcard in LIKE clause '{match}'."

    impact = "Forces a full table scan because B-Tree indexes cannot be traversed in reverse."
    fix_guidance = (
        "Use Full-Text Search (e.g., Elasticsearch, Postgres FTS) for substring searches."
    )


class FunctionOnIndexedColumnRule(ASTRule):
    """Detects functions wrapping columns in WHERE clause."""

    id = "PERF-IDX-001"
    name = "Function on Indexed Column"
    description = "Detects functions applied to columns in WHERE predicates (e.g. WHERE LOWER(email) = ...)."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    impact = "Prevents index usage, forces full table scan"
    fix_guidance = "Use functional indexes or rewrite predicate without wrapping function"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        where = ast.find(exp.Where)
        if where is None:
            return []

        for func in where.find_all(exp.Func):
            # Check if the function wraps a column reference
            if func.find(exp.Column):
                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Function '{type(func).__name__}' applied to column in WHERE clause prevents index usage.",
                        snippet=str(func),
                    )
                )
                break  # Report once per query
        return issues


class OrOnIndexedColumnsRule(PatternRule):
    """Detects OR conditions in WHERE clauses."""

    id = "PERF-IDX-004"
    name = "OR in WHERE Clause"
    description = "Detects OR conditions in WHERE clauses which can prevent index usage."
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    pattern = r"\bWHERE\b.+\bOR\b"
    message_template = "OR condition in WHERE clause detected: {match}"

    impact = "OR conditions can prevent index usage depending on the query planner"
    fix_guidance = "Consider rewriting as UNION ALL of two queries"


class DeepOffsetPaginationRule(PatternRule):
    """Detects OFFSET values over 1000."""

    id = "PERF-IDX-005"
    name = "Deep Offset Pagination"
    description = "Detects OFFSET values over 1000 which degrade pagination performance."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    pattern = r"\bOFFSET\s+([1-9]\d{3,})\b"
    message_template = "Deep pagination detected with large OFFSET: {match}"

    impact = "Database must scan and discard all rows before the offset"
    fix_guidance = "Use keyset/cursor pagination instead: WHERE id > last_seen_id LIMIT n"


class ImplicitTypeConversionRule(ASTRule):
    """Detects comparisons where column and value types likely mismatch."""

    id = "PERF-IDX-003"
    name = "Implicit Type Conversion on Indexed Column"
    description = (
        "Detects comparisons where column and value types likely mismatch, "
        "forcing implicit conversion that prevents index usage."
    )
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.EQ):
                left = node.this
                right = getattr(node, "expression", None)

                if isinstance(left, exp.Column) and isinstance(right, exp.Literal):
                    col_name = left.name.lower()

                    numeric_columns = {'id', 'user_id', 'account_id', 'order_id', 'product_id',
                                       'amount', 'quantity', 'price', 'count', 'total', 'age'}
                    string_columns = {'name', 'email', 'phone', 'address', 'code', 'status',
                                      'type', 'category', 'description', 'title', 'sku'}

                    is_string_literal = right.is_string

                    if any(nc in col_name for nc in numeric_columns) and is_string_literal:
                        issues.append(self.create_issue(
                            query=query,
                            message=f"Implicit type conversion: numeric column '{left.name}' compared with string literal",
                            snippet=str(node)[:100],
                            impact=(
                                "Implicit type conversion (e.g., WHERE varchar_col = 123) forces SQL Server to convert every row, "
                                "turning index seeks into full scans. This is one of the most common hidden performance killers."
                            ),
                            fix=Fix(
                                description="Match literal types to column types. Use WHERE id = 123 not WHERE id = '123'.",
                                replacement="",
                                is_safe=False,
                            ),
                        ))
                    elif any(sc in col_name for sc in string_columns) and not is_string_literal:
                        issues.append(self.create_issue(
                            query=query,
                            message=f"Implicit type conversion: string column '{left.name}' compared with numeric literal",
                            snippet=str(node)[:100],
                            impact=(
                                "Implicit type conversion (e.g., WHERE varchar_col = 123) forces SQL Server to convert every row, "
                                "turning index seeks into full scans. This is one of the most common hidden performance killers."
                            ),
                            fix=Fix(
                                description="Match literal types to column types. For strings, always quote: WHERE status = 'active' not WHERE status = active.",
                                replacement="",
                                is_safe=False,
                            ),
                        ))

        return issues


class CompositeIndexOrderViolationRule(ASTRule):
    """Detects WHERE clauses that filter on non-leading columns of common composite index patterns."""

    id = "PERF-IDX-006"
    name = "Composite Index Column Order Violation"
    description = (
        "Detects WHERE clauses that filter on non-leading columns of common composite index patterns, "
        "preventing index seek."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        composite_patterns = {
            ('tenant_id', 'user_id'): 'tenant_id',
            ('tenant_id', 'created_at'): 'tenant_id',
            ('user_id', 'created_at'): 'user_id',
            ('account_id', 'transaction_date'): 'account_id',
            ('store_id', 'product_id'): 'store_id',
            ('category_id', 'subcategory_id'): 'category_id',
            ('parent_id', 'child_id'): 'parent_id',
            ('org_id', 'department_id'): 'org_id',
        }

        for node in ast.walk():
            if isinstance(node, exp.Select):
                where_cols = self._get_where_columns(node)

                for (lead, secondary), required_lead in composite_patterns.items():
                    if secondary in where_cols and lead not in where_cols:
                        issues.append(self.create_issue(
                            query=query,
                            message=f"Filtering on '{secondary}' without leading column '{lead}' - composite index cannot be used efficiently",
                            snippet=str(node)[:100],
                            impact=(
                                "Composite indexes require the leading column in WHERE to enable index seek. "
                                "Filtering only on the secondary column forces a full index scan, often slower than a table scan."
                            ),
                            fix=Fix(
                                description="Include leading index columns in WHERE clause. Create additional indexes or reorder columns if needed.",
                                replacement="",
                                is_safe=False,
                            ),
                        ))

        return issues


class NonSargableOrConditionRule(ASTRule):
    """Detects OR conditions across different columns that prevent index usage."""

    id = "PERF-IDX-007"
    name = "Non-SARGable OR Condition"
    description = "Detects OR conditions across different columns that prevent index usage (non-SARGable)."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Or):
                left_cols = self._get_columns(node.this)
                right_cols = self._get_columns(getattr(node, "expression", None))

                if left_cols and right_cols and left_cols != right_cols:
                    issues.append(self.create_issue(
                        query=query,
                        message=f"OR condition across different columns ({', '.join(left_cols)} OR {', '.join(right_cols)}) prevents index usage",
                        snippet=str(node)[:100],
                        impact="OR conditions across columns force the optimizer to scan all rows. Neither index can be fully utilized.",
                        fix=Fix(
                            description="Rewrite as UNION ALL of two queries, each using its own index.",
                            replacement="",
                            is_safe=False,
                        ),
                    ))

        return issues

    def _get_columns(self, node: Any) -> set[str]:
        columns = set()
        if node:
            for col in node.find_all(exp.Column):
                columns.add(getattr(col, "name", "").lower())
        return columns


class CoalesceOnIndexedColumnRule(PatternRule):
    """Detects functions wrapping indexed columns in WHERE clause."""

    id = "PERF-IDX-008"
    name = "COALESCE/ISNULL/NVL on Indexed Column"
    description = "Detects COALESCE, ISNULL, NVL, or IFNULL wrapping indexed columns in WHERE clause, which prevents index usage."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    pattern = r"\bWHERE\b[^;]*\b(COALESCE|ISNULL|NVL|NVL2|IFNULL)\s*\(\s*\w+"
    message_template = "Function wrapping column in WHERE clause prevents index seek: {match}"

    impact = (
        "Wrapping a column in COALESCE/ISNULL forces evaluation of every row. "
        "WHERE ISNULL(status, 'x') = 'active' cannot use an index on status."
    )
    fix_guidance = (
        "Handle NULL explicitly: WHERE (status = 'active' OR (status IS NULL AND 'x' = 'active')). "
        "Or use a filtered index, computed column, or ensure column is NOT NULL."
    )


class NegationOnIndexedColumnRule(ASTRule):
    """Detects NOT, !=, <> conditions that typically cannot use indexes efficiently."""

    id = "PERF-IDX-009"
    name = "Negation on Indexed Column (NOT, !=, <>)"
    description = "Detects NOT, !=, <> conditions that typically cannot use indexes efficiently."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Not):
                issues.append(self.create_issue(
                    query=query,
                    message="NOT condition may prevent efficient index usage",
                    snippet=str(node)[:100],
                    impact=(
                        "Negation conditions force scanning all non-matching rows. "
                        "If 99% of rows match, you scan 99% of the table."
                    ),
                    fix=Fix(
                        description="Rewrite to positive condition if possible. Consider filtered indexes.",
                        replacement="",
                        is_safe=False,
                    ),
                ))

            if isinstance(node, exp.NEQ):
                issues.append(self.create_issue(
                    query=query,
                    message="Not-equal condition (<>, !=) typically cannot use index seek",
                    snippet=str(node)[:100],
                    impact=(
                        "Negation conditions typically prevent the query optimizer from performing efficient index seeks."
                    ),
                    fix=Fix(
                        description="Rewrite to IN or positive equality if values are known and limited.",
                        replacement="",
                        is_safe=False,
                    ),
                ))

        return issues
