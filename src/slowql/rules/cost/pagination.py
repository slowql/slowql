from __future__ import annotations

"""
Cost Pagination rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'CountStarForPaginationRule',
    'DeepPaginationWithoutCursorRule',
    'OffsetPaginationWithoutCoveringIndexRule',
]


class OffsetPaginationWithoutCoveringIndexRule(ASTRule):
    """Detects OFFSET-based pagination that must scan and discard rows."""

    id = "COST-PAGE-001"
    name = "OFFSET Pagination Without Index"
    description = (
        "Detects OFFSET-based pagination on non-indexed columns. In SQL, OFFSET "
        "forces the database to scan and discard rows, becoming exponentially "
        "slower and more expensive on later pages."
    )
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_PAGINATION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                offset_obj = node.args.get("offset")
                has_offset = offset_obj is not None
                if not has_offset:
                    has_offset = "OFFSET" in query.raw.upper()

                if has_offset:
                    order = node.args.get("order")
                    if order:
                        order_cols = []
                        if hasattr(order, "expressions"):
                            for expr in order.expressions:
                                if isinstance(expr, exp.Ordered):
                                    col = expr.this
                                    if isinstance(col, exp.Column):
                                        order_cols.append(col.name.lower())

                        likely_indexed = {"id", "created_at", "updated_at", "timestamp", "date"}
                        uses_pk = any(col in likely_indexed or col.endswith("_id") for col in order_cols)

                        if not uses_pk:
                            issues.append(
                                self.create_issue(
                                    query=query,
                                    message="OFFSET pagination on non-indexed column - cost increases linearly with page depth",
                                    snippet=str(node)[:100],
                                )
                            )
                    else:
                        issues.append(
                            self.create_issue(
                                query=query,
                                message="OFFSET pagination without ORDER BY - non-deterministic and expensive",
                                snippet=str(node)[:100],
                            )
                        )
        return issues

    impact = (
        "OFFSET 10000 forces the database to scan and discard 10,000 rows. On page 1000, "
        "you pay for scanning 1 million rows. In cloud databases, this means IOPS "
        "charges for wasted work."
    )
    fix_guidance = (
        "Use keyset/cursor pagination: WHERE id > last_seen_id ORDER BY id LIMIT 100. "
        "This maintains constant cost per page. For random access, use search indexing."
    )


class DeepPaginationWithoutCursorRule(ASTRule):
    """Detects deep pagination (>1000 offset) that should use keyset pagination."""

    id = "COST-PAGE-002"
    name = "Deep Pagination Without Cursor"
    description = (
        "Detects OFFSET values >1000, indicating deep pagination that should "
        "use a cursor/keyset approach for better performance and lower cost."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_PAGINATION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                offset_obj = node.args.get("offset")
                offset_value = None
                if offset_obj:
                    # sqlglot.expressions.Offset has the value in 'expression'
                    offset_expr = offset_obj.args.get("expression")
                    if isinstance(offset_expr, exp.Literal):
                        try:
                            offset_value = int(offset_expr.this)
                        except (ValueError, AttributeError):
                            pass
                    elif isinstance(offset_obj, exp.Literal): # Fallback
                        try:
                            offset_value = int(offset_obj.this)
                        except (ValueError, AttributeError):
                            pass
                else:
                    match = re.search(r'OFFSET\s+(\d+)', query.raw, re.IGNORECASE)
                    if match:
                        try:
                            offset_value = int(match.group(1))
                        except ValueError:
                            pass

                if offset_value and offset_value > 1000:
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"Deep pagination (OFFSET {offset_value}) - switch to cursor-based pagination",
                            snippet=str(node)[:100],
                        )
                    )
        return issues

    impact = (
        "Deep pagination (OFFSET > 1000) means scanning thousands of rows per page. "
        "Cloud databases charge per row scanned. Users on page 100+ generate 100x "
        "more cost than page 1 users."
    )
    fix_guidance = (
        "Implement cursor-based pagination: return cursor token with last record ID. "
        "Next page: WHERE id > cursor ORDER BY id LIMIT 100."
    )


class CountStarForPaginationRule(PatternRule):
    """Detects COUNT(*) queries used for total counts in pagination."""

    id = "COST-PAGE-003"
    name = "COUNT(*) for Pagination Total"
    description = (
        "Detects COUNT(*) queries used to calculate total pages, which can be "
        "expensive on large tables and is often unnecessary for user experience."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_PAGINATION

    pattern = r"\bSELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\b(?!.*\b(WHERE|LIMIT|TOP)\b)"
    message_template = "Expensive COUNT(*) for pagination total detected on unfiltered table."

    impact = (
        "COUNT(*) on large tables requires full table scan or index scan. For 100M "
        "row table, this can take 30+ seconds and cost significant IOPS. Users "
        "rarely navigate past page 3."
    )
    fix_guidance = (
        "Avoid showing total counts beyond page 10. Use approximate counts or "
        "cached counts updated periodically. Show 'More results' instead of page numbers."
    )
