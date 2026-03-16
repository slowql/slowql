"""Presto/Trino-specific cost rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "PrestoSelectStarPartitionedRule",
]


class PrestoSelectStarPartitionedRule(PatternRule):
    """Detects SELECT * on partitioned Hive tables in Presto/Trino."""

    id = "COST-PRESTO-001"
    name = "SELECT * on Partitioned Hive Table"
    description = (
        "SELECT * on partitioned Hive tables in Presto/Trino reads all "
        "partitions and all columns. Always filter on partition columns "
        "and specify needed columns to minimize data scanned."
    )
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("presto", "trino")

    pattern = r"\bSELECT\s+\*"
    message_template = "SELECT * on Presto/Trino — reads all columns and partitions: {match}"

    impact = (
        "Hive tables can have thousands of partitions and hundreds of "
        "columns. SELECT * reads everything, multiplying I/O and cost."
    )
    fix_guidance = (
        "Specify columns explicitly. Add WHERE on partition columns: "
        "WHERE dt = '2024-01-01'. Use SHOW PARTITIONS to understand layout."
    )
