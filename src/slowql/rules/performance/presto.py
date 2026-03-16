"""Presto/Trino-specific performance rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import PatternRule, Rule

__all__ = [
    "PrestoCrossJoinRule",
    "PrestoOrderByWithoutLimitRule",
]


class PrestoCrossJoinRule(PatternRule):
    """Detects implicit cross-joins in Presto/Trino."""

    id = "PERF-PRESTO-001"
    name = "Implicit Cross-Join on Distributed Engine"
    description = (
        "Comma-separated tables in FROM without JOIN conditions create "
        "implicit cross-joins. On Presto/Trino this shuffles data across "
        "all workers, generating O(n*m) intermediate rows."
    )
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_JOIN
    dialects = ("presto", "trino")

    pattern = r"\bFROM\s+\w+\s*,\s*\w+\b(?!.*\bJOIN\b)"
    message_template = "Implicit cross-join detected — use explicit JOIN with ON clause: {match}"

    impact = (
        "Cross-joins on distributed engines shuffle all data. Two 1M-row "
        "tables produce 1 trillion intermediate rows across workers."
    )
    fix_guidance = (
        "Replace comma-separated tables with explicit JOIN: "
        "FROM a JOIN b ON a.key = b.key."
    )


class PrestoOrderByWithoutLimitRule(Rule):
    """Detects ORDER BY without LIMIT on Presto/Trino."""

    id = "PERF-PRESTO-002"
    name = "ORDER BY Without LIMIT on Distributed Engine"
    description = (
        "ORDER BY without LIMIT on Presto/Trino requires gathering all "
        "data to the coordinator for global sorting, causing OOM on "
        "large result sets."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SORT
    dialects = ("presto", "trino")

    impact = (
        "All rows are sent to the coordinator node for sorting. This "
        "can exhaust coordinator memory and crash the query."
    )
    fix_guidance = (
        "Add LIMIT to bound the result. For analytics use window "
        "functions with PARTITION BY to sort within partitions."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        raw_upper = query.raw.upper()
        if "ORDER BY" not in raw_upper:
            return []
        if "LIMIT" in raw_upper:
            return []
        if query.query_type and query.query_type.upper() != "SELECT":
            return []
        return [self.create_issue(query=query, message="ORDER BY without LIMIT on Presto/Trino — coordinator OOM risk.", snippet=query.raw[:80])]
