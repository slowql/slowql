"""Spark/Databricks-specific cost rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import PatternRule, Rule

__all__ = [
    "SparkCacheTableWithoutFilterRule",
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


class SparkCacheTableWithoutFilterRule(PatternRule):
    """Detects CACHE TABLE without filter in Spark/Databricks."""

    id = "COST-SPARK-002"
    name = "CACHE TABLE Without Filter"
    description = (
        "CACHE TABLE without a filter caches the entire table in memory. "
        "For large tables this wastes executor memory and may cause OOM "
        "or evict more useful cached data."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("spark", "databricks")

    pattern = r"\bCACHE\s+(?:LAZY\s+)?TABLE\b(?!.*\bWHERE\b|.*\bOPTIONS\b)"
    message_template = "CACHE TABLE without filter — entire table loaded into memory: {match}"

    impact = (
        "Caching a 100GB table consumes 100GB of executor memory across "
        "the cluster. This evicts other cached data and may cause OOM."
    )
    fix_guidance = (
        "Cache only needed partitions: CACHE TABLE t OPTIONS ('partitionFilter' = "
        "\"dt = '2024-01-01'\"). Or use CACHE LAZY TABLE to defer until first access."
    )
