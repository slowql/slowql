"""
Quality Null handling rules.
"""

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
    "NullComparisonRule",
]


class NullComparisonRule(PatternRule):
    """Detects incorrect NULL comparisons using = or != instead of IS NULL / IS NOT NULL."""

    id = "QUAL-NULL-001"
    name = "Incorrect NULL Comparison"
    description = (
        "Detects comparisons using = NULL or != NULL (and <> NULL) instead of "
        "IS NULL or IS NOT NULL. In SQL, NULL = NULL evaluates to NULL (unknown), "
        "not TRUE, so these comparisons always return no rows."
    )
    severity = Severity.HIGH
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    remediation_mode = RemediationMode.SAFE_APPLY

    pattern = (
        r"(?<![A-Z_])\s*=\s*NULL\b"
        r"|\bNULL\s*=\s*(?![A-Z_])"
        r"|!=\s*NULL\b"
        r"|<>\s*NULL\b"
    )
    message_template = "Incorrect NULL comparison detected — use IS NULL or IS NOT NULL: {match}"

    impact = (
        "Using = NULL or != NULL silently returns zero rows regardless of actual "
        "NULL values, causing data to appear missing and logic to fail without errors."
    )
    fix_guidance = (
        "Replace '= NULL' with 'IS NULL' and '!= NULL' or '<> NULL' with "
        "'IS NOT NULL'. Use COALESCE() if a default value is needed instead of NULL handling."
    )

    def suggest_fix(self, query: Query) -> Fix | None:
        try:
            # != NULL / <> NULL → IS NOT NULL
            m = re.search(r"(!= NULL|<> NULL)", query.raw, re.IGNORECASE)
            if m:
                return Fix(
                    description="Replace '!= NULL' / '<> NULL' with 'IS NOT NULL'",
                    original=m.group(0),
                    replacement="IS NOT NULL",
                    confidence=FixConfidence.SAFE,
                    rule_id=self.id,
                    is_safe=True,
                )
            # = NULL → IS NULL (must come after != check to avoid partial match)
            m = re.search(r"(?<![!<>])=\s*NULL\b", query.raw, re.IGNORECASE)
            if m:
                return Fix(
                    description="Replace '= NULL' with 'IS NULL'",
                    original=m.group(0),
                    replacement="IS NULL",
                    confidence=FixConfidence.SAFE,
                    rule_id=self.id,
                    is_safe=True,
                )
        except Exception:
            return None
        return None

