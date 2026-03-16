"""ClickHouse-specific cost rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "ClickHouseSelectStarRule",
]


class ClickHouseSelectStarRule(PatternRule):
    """Detects SELECT * on ClickHouse MergeTree columnar storage."""

    id = "COST-CH-001"
    name = "SELECT * on ClickHouse Columnar Storage"
    description = (
        "ClickHouse MergeTree stores data in columnar format. SELECT * "
        "reads every column from disk even if only a few are needed, "
        "wasting I/O bandwidth and decompression CPU."
    )
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    dialects = ("clickhouse",)

    pattern = r"\bSELECT\s+\*"
    message_template = "SELECT * on ClickHouse — reads all columns from columnar storage: {match}"

    impact = (
        "ClickHouse column pruning is one of its key optimizations. "
        "SELECT * bypasses this, reading and decompressing every column."
    )
    fix_guidance = (
        "Always specify explicit column names. ClickHouse decompresses "
        "only requested columns, dramatically reducing I/O."
    )
