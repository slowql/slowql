"""Spark/Databricks-specific reliability rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import Rule

__all__ = [
    "SparkOverwriteWithoutPartitionRule",
]


class SparkOverwriteWithoutPartitionRule(Rule):
    """Detects INSERT OVERWRITE without partition predicate on Spark."""

    id = "REL-SPARK-001"
    name = "INSERT OVERWRITE Without Partition"
    description = (
        "INSERT OVERWRITE on Spark/Databricks without a partition predicate "
        "replaces ALL data in the target table. With static partition "
        "overwrite mode (default), this destroys the entire table."
    )
    severity = Severity.CRITICAL
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("spark", "databricks")

    impact = (
        "All existing data in the table is replaced. A query intended to "
        "update one partition destroys the entire table unless "
        "partitionOverwriteMode=dynamic is set."
    )
    fix_guidance = (
        "Specify partition: INSERT OVERWRITE TABLE t PARTITION (dt='2024-01-01'). "
        "Or enable dynamic mode: SET spark.sql.sources.partitionOverwriteMode=dynamic."
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
