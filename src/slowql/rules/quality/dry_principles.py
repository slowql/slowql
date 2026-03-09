"""
Quality Dry principles rules.
"""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'DuplicateConditionRule',
]


class DuplicateConditionRule(PatternRule):
    """Detects obvious duplicate WHERE conditions."""

    id = "QUAL-DRY-001"
    name = "Duplicate WHERE Condition"
    description = (
        "Detects WHERE clauses containing the same column compared to the same "
        "value twice with AND (e.g., WHERE status = 'active' AND status = 'active'). "
        "Duplicate conditions add noise, confuse readers, and may indicate a "
        "copy-paste error hiding a logic bug."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_DRY

    pattern = (
        r"\bWHERE\b.+\b(\w+)\s*=\s*('[^']*'|\d+)\s+AND\s+\1\s*=\s*\2"
    )
    message_template = "Duplicate WHERE condition detected — possible copy-paste error: {match}"

    impact = (
        "Duplicate conditions waste parser cycles and obscure intent. They often "
        "indicate a copy-paste error where the second condition should have been "
        "different (e.g., OR instead of AND, or a different value)."
    )
    fix_guidance = (
        "Remove the duplicate condition. If both conditions were intended to "
        "filter on different values, verify the logic — AND with two equal "
        "conditions on the same column always reduces to a single condition."
    )
