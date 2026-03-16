"""DuckDB-specific quality rules."""
from __future__ import annotations

import re

from slowql.core.models import (
    Category,
    Dimension,
    Fix,
    FixConfidence,
    Query,
    RemediationMode,
    Severity,
)
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
    remediation_mode = RemediationMode.SAFE_APPLY

    def suggest_fix(self, query: Query) -> Fix | None:
        """Replace type(val) with CAST(val AS type)."""
        match = re.search(
            r"\b(INTEGER|VARCHAR|FLOAT|DOUBLE|BOOLEAN|DATE|TIMESTAMP)\s*\(\s*(\w+)\s*\)",
            query.raw, re.IGNORECASE,
        )
        if not match:
            return None
        type_name = match.group(1)
        val = match.group(2)
        return Fix(
            description=f"Replace {type_name}({val}) with CAST({val} AS {type_name})",
            original=match.group(0),
            replacement=f"CAST({val} AS {type_name})",
            confidence=FixConfidence.SAFE,
            is_safe=True,
            rule_id=self.id,
        )

