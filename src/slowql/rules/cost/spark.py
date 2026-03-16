"""Spark/Databricks-specific cost rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import Rule

__all__ = [
    "SparkFullScanWithoutPartitionFilterRule",
]


class SparkFullScanWithoutPartitionFilterRule(Rule):
    """Detects queries without partition filter on Spark/Databricks."""

    id = "COST-SPARK-001"
    name = "Full Scan Without Partition Filter"
    description = (
        "Queries on partitioned Delta/Hive tables without a WHERE clause "
        "on the partition column read all partitions, multiplying I/O "
        "and compute cost."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("spark", "databricks")

    impact = (
        "A partitioned table with 365 daily partitions will read 365x "
        "more data without a partition filter. Databricks charges per DBU."
    )
    fix_guidance = (
        "Always filter on partition columns: WHERE date = '2024-01-01'. "
        "Enable spark.sql.sources.partitionOverwriteMode=dynamic for "
        "safe overwrites."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if query.query_type and query.query_type.upper() not in ("SELECT", "DELETE", "UPDATE"):
            return []
        raw_upper = query.raw.upper()
        if "WHERE" in raw_upper:
            return []
        if "SELECT" not in raw_upper:
            return []
        return [self.create_issue(query=query, message="Query without WHERE on Spark/Databricks — full partition scan.", snippet=query.raw[:80])]
