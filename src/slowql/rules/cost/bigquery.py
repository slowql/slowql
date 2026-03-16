"""BigQuery-specific cost rules."""
from __future__ import annotations

from typing import ClassVar

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = ["BigQueryMissingLimitRule", "BigQuerySelectStarCostRule"]

class BigQuerySelectStarCostRule(PatternRule):
    """Detects SELECT * in BigQuery which scans all columns."""

    id = "COST-BQ-001"
    name = "SELECT * in BigQuery Scans All Columns"
    dialects: ClassVar[tuple[str, ...]] = ("bigquery",)
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    pattern = r"\bSELECT\s+\*"
    message_template = "SELECT * in BigQuery scans all columns — billed by bytes scanned: {match}"
    impact = (
        "BigQuery charges per byte scanned. SELECT * on a 1TB table with 50 columns "
        "costs 50x more than selecting only the 1 column you need. "
        "At $5/TB, a daily job doing SELECT * can cost thousands per month unnecessarily."
    )
    fix_guidance = (
        "Always specify only the columns you need. "
        "Use column pruning: SELECT id, name, date FROM table. "
        "Partition and cluster tables on frequently filtered columns to reduce scan cost."
    )

class BigQueryMissingLimitRule(PatternRule):
    """Detects queries without LIMIT in BigQuery."""

    id = "COST-BQ-002"
    name = "BigQuery Query Without LIMIT"
    dialects: ClassVar[tuple[str, ...]] = ("bigquery",)
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    pattern = r"\bSELECT\b(?![\s\S]*\bLIMIT\b)"
    message_template = "SELECT without LIMIT in BigQuery — full table scan billed: {match}"
    impact = (
        "BigQuery bills for bytes scanned regardless of rows returned. "
        "An exploratory query without LIMIT on a large table incurs full scan cost "
        "even if you only need a sample of the data."
    )
    fix_guidance = (
        "Add LIMIT for exploratory queries: SELECT * FROM t LIMIT 1000. "
        "Use table previews in the console for sampling. "
        "Use _PARTITIONTIME or _PARTITIONDATE filters to limit scan range."
    )
