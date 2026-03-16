"""ClickHouse-specific reliability rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import Rule

__all__ = [
    "ClickHouseSelectWithoutFinalRule",
]


class ClickHouseSelectWithoutFinalRule(Rule):
    """Detects SELECT without FINAL on ReplacingMergeTree tables."""

    id = "REL-CH-001"
    name = "SELECT Without FINAL on ReplacingMergeTree"
    description = (
        "ReplacingMergeTree tables may contain duplicate rows until "
        "background merges complete. SELECT without FINAL returns "
        "unmerged duplicates, producing incorrect results."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("clickhouse",)

    impact = (
        "Queries return duplicate rows that should have been deduplicated. "
        "Aggregations like COUNT and SUM return inflated values."
    )
    fix_guidance = (
        "Add FINAL keyword: SELECT * FROM table FINAL WHERE ... "
        "Note: FINAL forces a merge at query time which adds latency. "
        "For high-throughput reads, use OPTIMIZE TABLE periodically."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if query.query_type and query.query_type.upper() != "SELECT":
            return []
        raw_upper = query.raw.upper()
        if "FINAL" in raw_upper:
            return []
        if "REPLACING" in raw_upper or "COLLAPSING" in raw_upper:
            return [self.create_issue(query=query, message="SELECT without FINAL on ReplacingMergeTree — may return unmerged duplicates.", snippet=query.raw[:80])]
        return []
