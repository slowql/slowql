"""DuckDB-specific quality rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "DuckDBOldStyleCastRule",
]


class DuckDBOldStyleCastRule(PatternRule):
    """Detects deprecated old-style type casts in DuckDB."""

    id = "QUAL-DUCK-001"
    name = "Deprecated Old-Style Type Cast"
    description = (
        "DuckDB supports PostgreSQL-style :: casts but also allows "
        "old-style type(value) syntax which is less readable and may "
        "be confused with function calls."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN
    dialects = ("duckdb",)

    pattern = r"\b(?:INTEGER|VARCHAR|FLOAT|DOUBLE|BOOLEAN|DATE|TIMESTAMP)\s*\(\s*\w+\s*\)"
    message_template = "Old-style type cast detected — use CAST or :: syntax: {match}"

    impact = (
        "Old-style casts are visually ambiguous with function calls "
        "and reduce code readability."
    )
    fix_guidance = (
        "Use CAST(value AS type) or value::type instead of type(value)."
    )
