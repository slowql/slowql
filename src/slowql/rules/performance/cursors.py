from __future__ import annotations

"""
Performance Cursors rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'CursorDeclarationRule',
    'NestedLoopJoinHintRule',
    'WhileLoopPatternRule',
]


class CursorDeclarationRule(PatternRule):
    """Detects CURSOR declarations, which indicate row-by-row processing."""

    id = "PERF-CURSOR-001"
    name = "Cursor Declaration"
    description = "Detects CURSOR declarations, which indicate row-by-row processing (RBAR - Row By Agonizing Row)."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_CURSOR

    pattern = r"\bDECLARE\s+\w+\s+CURSOR\b"
    message_template = "Cursor declaration detected: {match}"

    impact = (
        "Cursors process one row at a time, requiring round-trips and preventing set-based optimizations. "
        "Cursor operations are typically 10-100x slower than equivalent set-based SQL."
    )
    fix_guidance = "Rewrite using set-based operations: UPDATE...FROM, MERGE, window functions. If cursor is truly necessary, use FAST_FORWARD READ_ONLY."


class WhileLoopPatternRule(PatternRule):
    """Detects WHILE loops that may indicate row-by-row processing."""

    id = "PERF-CURSOR-002"
    name = "WHILE Loop Pattern"
    description = "Detects WHILE loops that may indicate row-by-row processing."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_CURSOR

    pattern = r"\bWHILE\s+[\(@].*\bBEGIN\b"
    message_template = "WHILE loop detected: {match}"

    impact = (
        "WHILE loops in SQL often indicate procedural thinking applied to a set-based language. "
        "Each iteration may execute separate queries, multiplying execution time."
    )
    fix_guidance = "Replace WHILE loops with set-based operations. Use recursive CTEs for hierarchical processing."


class NestedLoopJoinHintRule(PatternRule):
    """Detects LOOP JOIN hints that force nested loop joins."""

    id = "PERF-CURSOR-003"
    name = "Nested Loop Join Hint"
    description = "Detects LOOP JOIN hints that force nested loop joins, often inappropriate for large datasets."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_CURSOR

    pattern = r"\b(LOOP\s+JOIN|INNER\s+LOOP\s+JOIN|LEFT\s+LOOP\s+JOIN|OPTION\s*\(\s*LOOP\s+JOIN\s*\))"
    message_template = "Nested loop join hint detected: {match}"

    impact = (
        "Forced nested loop joins perform O(n*m) comparisons. For large tables, this is catastrophic. "
        "The optimizer usually knows better."
    )
    fix_guidance = "Remove join hints and let the optimizer choose. If hint is necessary, document why."
