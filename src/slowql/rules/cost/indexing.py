from __future__ import annotations

"""
Cost Indexing rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'DuplicateIndexSignalRule',
    'MissingCoveringIndexOpportunityRule',
    'OverIndexedTableSignalRule',
    'RedundantIndexColumnOrderRule',
]


# =============================================================================
class DuplicateIndexSignalRule(PatternRule):
    """Detects CREATE INDEX statements that may duplicate existing indexes."""

    id = "COST-IDX-001"
    name = "Duplicate Index Signal"
    description = (
        "Detects CREATE INDEX statements which may duplicate existing indexes "
        "(same columns, different name). Duplicate indexes waste storage and slow down writes."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_INDEX_WASTE

    pattern = r"\bCREATE\s+INDEX\s+\w+\s+ON\s+(\w+)\s*\(([^)]+)\)"
    message_template = "Duplicate index signal detected: {match}. Verify if index already exists."

    impact = (
        "Duplicate indexes waste storage (each index = 100% of indexed data), slow "
        "down writes (every INSERT/UPDATE maintains all indexes), and cost money in "
        "cloud storage charges."
    )
    fix_guidance = (
        "Query system catalog to find duplicates (e.g., pg_indexes). Keep only the "
        "most selective index. Use covering indexes instead of multiple single-column indexes."
    )


class OverIndexedTableSignalRule(PatternRule):
    """Flags tables that likely already have many indexes."""

    id = "COST-IDX-002"
    name = "Over-Indexed Table Signal"
    description = (
        "Flags CREATE INDEX on tables that likely already have many indexes, "
        "causing massive write penalties and increased cloud storage costs."
    )
    severity = Severity.LOW
    dimension = Dimension.COST
    category = Category.COST_INDEX_WASTE

    pattern = r"(CREATE\s+INDEX\s+\w+\s+ON\s+(\w+)[\s\S]*?){3,}"
    message_template = "Over-indexed table signal: multiple CREATE INDEX statements found for the same table."

    impact = (
        "Tables with 10+ indexes pay massive write penalties. Each INSERT updates all "
        "indexes. Write throughput can drop 90%. Cloud databases charge for IOPS "
        "consumed by index maintenance."
    )
    fix_guidance = (
        "Audit index usage and drop unused indexes. Consolidate into composite or "
        "covering indexes."
    )


class MissingCoveringIndexOpportunityRule(ASTRule):
    """Detects SELECT with WHERE + specific columns that could benefit from covering index."""

    id = "COST-IDX-003"
    name = "Missing Covering Index Opportunity"
    description = (
        "Detects SELECT with WHERE filters and specific columns that could benefit "
        "from a covering index, eliminating expensive table lookups."
    )
    severity = Severity.LOW
    dimension = Dimension.COST
    category = Category.COST_INDEX_OPTIMIZATION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Select):
                where = node.args.get("where")
                where_cols = set()
                if where:
                    for col in where.find_all(exp.Column):
                        where_cols.add(col.name.lower())

                select_cols = set()
                has_star = False
                for expr in node.expressions:
                    if isinstance(expr, exp.Star):
                        has_star = True
                        break
                    elif isinstance(expr, exp.Column):
                        select_cols.add(expr.name.lower())
                    elif isinstance(expr, exp.Alias) and isinstance(expr.this, exp.Column):
                        select_cols.add(expr.this.name.lower())

                if where_cols and select_cols and not has_star:
                    total_cols = where_cols | select_cols
                    if 2 <= len(total_cols) <= 5:
                        issues.append(
                            self.create_issue(
                                query=query,
                                message=f"Covering index opportunity: index on {sorted(where_cols)} INCLUDE {sorted(select_cols - where_cols)}",
                                snippet=str(node)[:100],
                            )
                        )
        return issues

    impact = (
        "Non-covering indexes require key lookup - reading index then reading table. "
        "Covering indexes eliminate table access, reducing I/O by 50-90%."
    )
    fix_guidance = (
        "Create covering index: CREATE INDEX idx_name ON table(where_cols) INCLUDE (select_cols). "
        "Monitor index size vs benefit."
    )


class RedundantIndexColumnOrderRule(PatternRule):
    """Detects composite index creation where column order may be suboptimal."""

    id = "COST-IDX-004"
    name = "Redundant Index Column Order"
    description = (
        "Detects composite index creation where column order may not match common "
        "query patterns, leading to wasted indexes and slower queries."
    )
    severity = Severity.INFO
    dimension = Dimension.COST
    category = Category.COST_INDEX_OPTIMIZATION

    pattern = r"\bCREATE\s+INDEX\s+\w+\s+ON\s+\w+\s*\((\w+)\s*,\s*(\w+)"
    message_template = "Composite index column order signal: check if order matches query patterns: {match}"

    impact = (
        "Index (col_B, col_A) cannot optimize WHERE col_A = ?. Column order matters. "
        "Wrong order = wasted index and slower queries."
    )
    fix_guidance = (
        "Order index columns by selectivity and query usage. For queries filtering "
        "col_A then col_B, use INDEX(col_A, col_B)."
    )
