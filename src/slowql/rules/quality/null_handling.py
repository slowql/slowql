from __future__ import annotations

"""
Quality Null handling rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'NullComparisonRule',
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
