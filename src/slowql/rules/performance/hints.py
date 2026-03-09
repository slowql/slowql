from __future__ import annotations

"""
Performance Hints rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'IndexHintRule',
    'ParallelQueryHintRule',
    'QueryOptimizerHintRule',
]


class QueryOptimizerHintRule(PatternRule):
    """Detects query hints that override optimizer decisions."""

    id = "PERF-HINT-001"
    name = "Query Optimizer Hint"
    description = "Detects query hints that override optimizer decisions."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_HINTS

    pattern = r"\bOPTION\s*\(\s*(FORCE\s+ORDER|HASH\s+JOIN|MERGE\s+JOIN|LOOP\s+JOIN|FAST\s+\d+|RECOMPILE|OPTIMIZE\s+FOR|MAXDOP|QUERYTRACEON|USE\s+PLAN)\b"
    message_template = "Query optimizer hint detected: {match}"

    impact = (
        "Query hints freeze execution plans. As data grows and distribution changes, hinted plans become suboptimal. "
        "Hints hide underlying issues (missing indexes, bad statistics)."
    )
    fix_guidance = "Remove hints and fix root cause: update statistics, add indexes, simplify query."


class IndexHintRule(PatternRule):
    """Detects forced index usage hints."""

    id = "PERF-HINT-002"
    name = "Index Hint"
    description = "Detects forced index usage hints."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_HINTS

    pattern = r"\b(FORCE\s+INDEX|USE\s+INDEX|IGNORE\s+INDEX|WITH\s*\(\s*INDEX\s*[=(])\b"
    message_template = "Index hint detected: {match}"

    impact = (
        "Index hints force specific index usage regardless of statistics. "
        "When data changes, the forced index may become suboptimal, but the hint remains."
    )
    fix_guidance = "Let the optimizer choose indexes. If it chooses wrong, update statistics or create better indexes."


class ParallelQueryHintRule(PatternRule):
    """Detects MAXDOP hints that override server parallelism settings."""

    id = "PERF-HINT-003"
    name = "Parallel Query Hint"
    description = "Detects MAXDOP hints that override server parallelism settings."
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_HINTS

    pattern = r"\bOPTION\s*\([^)]*MAXDOP\s+\d+"
    message_template = "Parallel query hint (MAXDOP) detected: {match}"

    impact = (
        "MAXDOP hints override server-level parallelism. MAXDOP 1 forces single-threaded execution. "
        "High MAXDOP values can starve other queries of CPU."
    )
    fix_guidance = "Use server or database-level MAXDOP settings. Per-query hints are rarely justified."
