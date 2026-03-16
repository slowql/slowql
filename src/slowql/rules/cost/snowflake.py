"""Snowflake-specific cost rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = ["SnowflakeCopyIntoWithoutFileFormatRule", "SnowflakeSelectStarCostRule"]

class SnowflakeSelectStarCostRule(PatternRule):
    """Detects SELECT * in Snowflake which scans all micro-partitions."""

    id = "COST-SF-001"
    name = "SELECT * Wastes Snowflake Credits"
    dialects = ("snowflake",)
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE
    pattern = r"\bSELECT\s+\*"
    message_template = "SELECT * in Snowflake scans all micro-partitions — wastes warehouse credits: {match}"
    impact = (
        "Snowflake stores data in columnar micro-partitions. SELECT * prevents column pruning "
        "and forces scanning all partitions. On large tables this multiplies credit consumption "
        "and increases query time, directly increasing warehouse cost."
    )
    fix_guidance = (
        "Select only needed columns. Use clustering keys on large tables. "
        "Consider materialized views for frequently queried column subsets."
    )

class SnowflakeCopyIntoWithoutFileFormatRule(PatternRule):
    """Detects COPY INTO without explicit FILE_FORMAT in Snowflake."""

    id = "COST-SF-002"
    name = "COPY INTO Without Explicit File Format"
    dialects = ("snowflake",)
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    pattern = r"\bCOPY\s+INTO\b(?![\s\S]*\bFILE_FORMAT\b)"
    message_template = "COPY INTO without FILE_FORMAT — relies on default format settings: {match}"
    impact = (
        "COPY INTO without FILE_FORMAT relies on default or stage-level format settings. "
        "If defaults change or the stage is reconfigured, data loading silently fails "
        "or loads malformed data without error."
    )
    fix_guidance = (
        "Always specify FILE_FORMAT explicitly: "
        "COPY INTO table FROM stage FILE_FORMAT = (TYPE = 'CSV' FIELD_DELIMITER = ',')."
    )
