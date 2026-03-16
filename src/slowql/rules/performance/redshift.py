"""Redshift-specific performance rules."""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import PatternRule, Rule

__all__ = [
    "NotInOnRedshiftRule",
    "OrderByWithoutLimitRedshiftRule",
    "RedshiftSelectStarRule",
]


class RedshiftSelectStarRule(PatternRule):
    """Detects SELECT * on Redshift columnar tables."""

    id = "PERF-RS-001"
    name = "SELECT * on Redshift Columnar Storage"
    description = (
        "Redshift stores data in a columnar format. SELECT * reads every "
        "column from disk even if only a few are needed, wasting I/O and "
        "network bandwidth."
    )
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("redshift",)

    pattern = r"\bSELECT\s+\*"
    message_template = "SELECT * on Redshift — reads all columns from columnar storage: {match}"

    impact = (
        "Redshift charges for bytes scanned. SELECT * on a 100-column table "
        "reads 100x more data than selecting the 1 column needed."
    )
    fix_guidance = (
        "Always specify explicit column names. Use CTAS or views to reduce "
        "column exposure."
    )


class OrderByWithoutLimitRedshiftRule(Rule):
    """Detects ORDER BY without LIMIT on Redshift distributed queries."""

    id = "PERF-RS-002"
    name = "ORDER BY Without LIMIT on Redshift"
    description = (
        "ORDER BY without LIMIT on Redshift requires redistributing all "
        "rows to a single node for sorting, causing massive network traffic "
        "and memory pressure on the leader node."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SORT
    dialects = ("redshift",)

    impact = (
        "All rows must be sent to the leader node for global sorting. "
        "On large tables this can OOM the leader or take very long."
    )
    fix_guidance = (
        "Add LIMIT to bound the result. For analytics, use window functions "
        "with PARTITION BY to sort within partitions."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        raw_upper = query.raw.upper()
        if "ORDER BY" not in raw_upper:
            return []
        if "LIMIT" in raw_upper or "TOP" in raw_upper:
            return []
        if query.query_type and query.query_type.upper() != "SELECT":
            return []
        return [self.create_issue(query=query, message="ORDER BY without LIMIT on Redshift — full redistribution to leader node.", snippet=query.raw[:80])]


class NotInOnRedshiftRule(PatternRule):
    """Detects NOT IN on Redshift which causes hash join explosion."""

    id = "PERF-RS-003"
    name = "NOT IN on Redshift (Hash Join Explosion)"
    description = (
        "NOT IN on Redshift generates a nested loop anti-join or large hash "
        "table. With NULLs in the subquery, Redshift cannot optimize this "
        "and must scan all rows."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("redshift",)

    pattern = r"\bNOT\s+IN\s*\(\s*SELECT\b"
    message_template = "NOT IN with subquery on Redshift — use NOT EXISTS or LEFT JOIN/NULL: {match}"

    impact = (
        "NOT IN forces Redshift to build a hash table of the entire subquery "
        "result. With NULLs present, it degrades to a nested loop."
    )
    fix_guidance = (
        "Replace NOT IN (SELECT ...) with NOT EXISTS (SELECT 1 FROM ... WHERE ...) "
        "or LEFT JOIN ... WHERE key IS NULL."
    )
