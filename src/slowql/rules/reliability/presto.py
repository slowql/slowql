"""Presto/Trino-specific reliability rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import Rule

__all__ = [
    "PrestoInsertOverwriteWithoutPartitionRule",
]


class PrestoInsertOverwriteWithoutPartitionRule(Rule):
    """Detects INSERT OVERWRITE without partition specification."""

    id = "REL-PRESTO-001"
    name = "INSERT OVERWRITE Without Partition"
    description = (
        "INSERT OVERWRITE without a partition specification in Presto/Trino "
        "replaces ALL data in the target table. This is almost always "
        "unintentional and causes catastrophic data loss."
    )
    severity = Severity.CRITICAL
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("presto", "trino")

    impact = (
        "All existing data in the table is replaced. Without partition "
        "specification, a query meant to update one day's data destroys "
        "the entire table."
    )
    fix_guidance = (
        "Always specify partition: INSERT OVERWRITE table PARTITION (dt='2024-01-01'). "
        "Or use INSERT INTO for append-only semantics."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if not self._has_pattern(query.raw, r"\bINSERT\s+OVERWRITE\b"):
            return []
        raw_upper = query.raw.upper()
        if "PARTITION" in raw_upper:
            return []
        return [self.create_issue(query=query, message="INSERT OVERWRITE without PARTITION — will replace ALL data in target table.", snippet=query.raw[:80])]
