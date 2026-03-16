"""Snowflake-specific cost rules."""
from __future__ import annotations

from typing import ClassVar

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = ["SnowflakeCopyIntoWithoutFileFormatRule", "SnowflakeCopyWithoutOnErrorRule", "SnowflakeOrderByVariantRule", "SnowflakeSelectStarCostRule", "SnowflakeVariantInWhereRule"]

class SnowflakeSelectStarCostRule(PatternRule):
    """Detects SELECT * in Snowflake which scans all micro-partitions."""

    id = "COST-SF-001"
    name = "SELECT * Wastes Snowflake Credits"
    dialects: ClassVar[tuple[str, ...]] = ("snowflake",)
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
    dialects: ClassVar[tuple[str, ...]] = ("snowflake",)
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


class SnowflakeCopyWithoutOnErrorRule(PatternRule):
    """Detects COPY INTO without ON_ERROR in Snowflake."""

    id = "REL-SF-001"
    name = "COPY INTO Without ON_ERROR"
    description = "COPY INTO defaults to ABORT_STATEMENT on first error — set ON_ERROR explicitly."
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("snowflake",)
    pattern = r"\bCOPY\s+INTO\b(?!.*\bON_ERROR\b)"
    message_template = "COPY INTO without explicit ON_ERROR setting: {match}"
    impact = "A single malformed row aborts the entire load."
    fix_guidance = "Add ON_ERROR = 'CONTINUE' or 'SKIP_FILE'. Use VALIDATION_MODE for rejected rows."


class SnowflakeVariantInWhereRule(PatternRule):
    """Detects filtering on VARIANT columns without explicit CAST in Snowflake."""

    id = "PERF-SF-001"
    name = "VARIANT Column in WHERE Without CAST"
    description = "VARIANT columns in WHERE without CAST prevent micro-partition pruning."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("snowflake",)
    pattern = r"\bWHERE\b.*:[\w.]+"
    message_template = "VARIANT column access in WHERE — add explicit CAST for pruning: {match}"
    impact = "Without CAST, Snowflake scans all micro-partitions."
    fix_guidance = "Cast VARIANT: WHERE data:field::STRING = 'value'."


class SnowflakeOrderByVariantRule(PatternRule):
    """Detects ORDER BY on VARIANT column in Snowflake."""

    id = "PERF-SF-002"
    name = "ORDER BY on VARIANT Column"
    description = "Sorting on VARIANT requires runtime type resolution — slower than typed columns."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SORT
    dialects = ("snowflake",)
    pattern = r"\bORDER\s+BY\b.*:[\w.]+"
    message_template = "ORDER BY on VARIANT column — slow runtime type resolution: {match}"
    impact = "VARIANT sorting inspects type per row, adding significant overhead."
    fix_guidance = "Cast in ORDER BY: ORDER BY data:field::NUMBER."
