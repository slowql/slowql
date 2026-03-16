"""Spark/Databricks-specific performance rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import PatternRule, Rule

__all__ = [
    "SparkBroadcastHintRule",
    "SparkUdfInWhereRule",
]


class SparkBroadcastHintRule(PatternRule):
    """Detects BROADCAST hint on potentially large tables in Spark."""

    id = "PERF-SPARK-001"
    name = "BROADCAST Hint on Large Table"
    description = (
        "/*+ BROADCAST(table) */ forces Spark to broadcast the entire table "
        "to all executors. If the table is large, this causes OOM on "
        "executors and driver."
    )
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_JOIN
    dialects = ("spark", "databricks")

    pattern = r"/\*\+\s*BROADCAST\s*\("
    message_template = "BROADCAST hint detected — ensure table fits in executor memory: {match}"

    impact = (
        "Broadcasting a table larger than spark.sql.autoBroadcastJoinThreshold "
        "(default 10MB) causes OOM. The entire table is serialized and sent "
        "to every executor."
    )
    fix_guidance = (
        "Remove BROADCAST hint and let Spark auto-decide. If needed, verify "
        "table size is under autoBroadcastJoinThreshold. Use EXPLAIN to "
        "confirm join strategy."
    )


class SparkUdfInWhereRule(Rule):
    """Detects UDF usage in WHERE clause preventing predicate pushdown."""

    id = "PERF-SPARK-002"
    name = "UDF in WHERE Prevents Pushdown"
    description = (
        "User-defined functions (UDFs) in WHERE clauses prevent Spark from "
        "pushing predicates down to the data source. This forces Spark to "
        "read all data then filter in-memory."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("spark", "databricks")

    impact = (
        "Without pushdown, Spark reads the entire table/partition from "
        "storage. For Parquet/Delta files this bypasses column pruning "
        "and row group filtering."
    )
    fix_guidance = (
        "Replace UDFs with built-in Spark SQL functions which support "
        "pushdown. If UDF is necessary, pre-filter with pushable "
        "predicates first."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if not self._has_pattern(query.raw, r"\bWHERE\b.*\b(?:udf|UDF)\s*\("):
            return []
        return [self.create_issue(query=query, message="UDF in WHERE clause — prevents predicate pushdown to data source.", snippet=query.raw[:80])]
