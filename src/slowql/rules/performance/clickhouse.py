"""ClickHouse-specific performance rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import PatternRule, Rule

__all__ = [
    "ClickHouseJoinWithoutGlobalRule",
    "ClickHouseMutationRule",
    "ClickHouseSelectWithoutPrewhereRule",
]


class ClickHouseSelectWithoutPrewhereRule(PatternRule):
    """Detects SELECT without PREWHERE on ClickHouse MergeTree tables."""

    id = "PERF-CH-001"
    name = "SELECT Without PREWHERE"
    description = (
        "ClickHouse PREWHERE filters data before reading non-filtered columns, "
        "dramatically reducing I/O on wide MergeTree tables. WHERE reads all "
        "columns first then filters."
    )
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("clickhouse",)

    pattern = r"\bSELECT\b.*\bWHERE\b(?!.*\bPREWHERE\b)"
    message_template = "WHERE without PREWHERE — consider PREWHERE for I/O reduction: {match}"

    impact = (
        "Without PREWHERE, ClickHouse reads all columns from disk before "
        "filtering. PREWHERE reads only the filter column first, skipping "
        "granules that don't match."
    )
    fix_guidance = (
        "Move selective filter conditions from WHERE to PREWHERE. ClickHouse "
        "auto-optimizes simple conditions, but explicit PREWHERE guarantees it."
    )


class ClickHouseJoinWithoutGlobalRule(Rule):
    """Detects JOIN without GLOBAL on ClickHouse distributed tables."""

    id = "PERF-CH-002"
    name = "JOIN Without GLOBAL on Distributed Table"
    description = (
        "On ClickHouse distributed tables, JOIN without GLOBAL sends the "
        "right-side subquery to every shard independently. GLOBAL JOIN "
        "executes it once and broadcasts the result."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_JOIN
    dialects = ("clickhouse",)

    impact = (
        "Without GLOBAL, each shard executes the right-side subquery "
        "independently. For N shards this means N redundant executions."
    )
    fix_guidance = (
        "Use GLOBAL JOIN or GLOBAL IN for distributed subqueries: "
        "SELECT * FROM dist_table GLOBAL JOIN (SELECT ...) USING key."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        raw_upper = query.raw.upper()
        if "JOIN" not in raw_upper:
            return []
        if "GLOBAL" in raw_upper:
            return []
        if not self._has_pattern(query.raw, r"\bJOIN\s*\(\s*SELECT\b"):
            return []
        return [self.create_issue(query=query, message="JOIN with subquery without GLOBAL — redundant execution on each shard.", snippet=query.raw[:80])]


class ClickHouseMutationRule(PatternRule):
    """Detects ALTER TABLE UPDATE/DELETE mutations in ClickHouse."""

    id = "PERF-CH-003"
    name = "ClickHouse Mutation (ALTER UPDATE/DELETE)"
    description = (
        "ClickHouse mutations (ALTER TABLE UPDATE/DELETE) are heavy "
        "asynchronous operations that rewrite entire data parts. They "
        "are not designed for frequent row-level modifications."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("clickhouse",)

    pattern = r"\bALTER\s+TABLE\s+\w+\s+(?:UPDATE|DELETE)\b"
    message_template = "ClickHouse mutation detected — heavy async part rewrite: {match}"

    impact = (
        "Mutations rewrite entire data parts asynchronously. Frequent "
        "mutations queue up and consume disk I/O and CPU. They are not "
        "transactional and cannot be rolled back."
    )
    fix_guidance = (
        "Use ReplacingMergeTree or CollapsingMergeTree for logical "
        "deletes/updates. Reserve ALTER TABLE mutations for rare bulk "
        "corrections."
    )
