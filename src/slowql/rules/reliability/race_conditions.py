"""
Reliability Race conditions rules.
"""

from __future__ import annotations

from typing import Any

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    "MergeWithoutHoldlockRule",
    "ReadModifyWriteLockingRule",
    "TOCTOUPatternRule",
]


class ReadModifyWriteLockingRule(ASTRule):
    """Detects read-modify-write patterns without locking."""

    id = "REL-RACE-001"
    name = "Read-Modify-Write Without Lock"
    description = (
        "Detects patterns suggesting read-modify-write cycles (SELECT followed by "
        "UPDATE on same table) without FOR UPDATE lock or transaction isolation."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_RACE_CONDITION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        query_upper = query.raw.upper()

        # Pattern: SELECT without FOR UPDATE, then UPDATE same table
        # Note: This heuristic checks if both SELECT and UPDATE exist in the same batch
        has_select = "SELECT" in query_upper
        has_update = "UPDATE" in query_upper
        has_for_update = "FOR UPDATE" in query_upper
        has_serializable = "SERIALIZABLE" in query_upper

        if has_select and has_update and not (has_for_update or has_serializable):
            issues.append(
                self.create_issue(
                    query=query,
                    message="Read-modify-write pattern without FOR UPDATE or SERIALIZABLE isolation — race condition risk.",
                    snippet=query.raw[:100],
                )
            )

        return issues

    impact = (
        "Read-modify-write without locks causes lost updates. Two concurrent "
        "transactions read the same value, both modify, both write — one update is lost. "
        "Classic race condition."
    )
    fix_guidance = (
        "Use SELECT ... FOR UPDATE to lock rows during read-modify-write. Or use "
        "SERIALIZABLE isolation. Better: use atomic UPDATE with single statement."
    )


class TOCTOUPatternRule(PatternRule):
    """Detects Time-of-Check-Time-of-Use patterns."""

    id = "REL-RACE-002"
    name = "TOCTOU Pattern"
    description = (
        "Detects IF EXISTS / IF NOT EXISTS checks followed by INSERT/UPDATE/DELETE "
        "without proper locking, creating time-of-check-time-of-use vulnerabilities."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_RACE_CONDITION

    pattern = r"\bIF\s+(NOT\s+)?EXISTS\s*\(\s*SELECT[^)]+\)[^;]*\b(INSERT|UPDATE|DELETE)\b"
    message_template = (
        "Potential TOCTOU race condition detected: IF EXISTS check followed by modification."
    )

    impact = (
        "TOCTOU vulnerabilities allow race conditions: checking if row exists, then acting, "
        "leaves a gap where another transaction can change state. Common in user "
        "registration, inventory management."
    )
    fix_guidance = (
        "Use atomic operations: INSERT ... ON CONFLICT, MERGE, or INSERT ... WHERE NOT "
        "EXISTS as single statement. If IF is required, wrap in SERIALIZABLE "
        "transaction or use advisory locks."
    )


class MergeWithoutHoldlockRule(Rule):
    """Detects MERGE statements without HOLDLOCK hint in T-SQL."""

    id = "REL-TSQL-002"
    name = "MERGE Without HOLDLOCK"
    description = (
        "In SQL Server the MERGE statement is not atomic by default. Without "
        "WITH (HOLDLOCK) on the target table, concurrent MERGE executions can "
        "cause primary key violations or lost updates due to a race between "
        "the matched/not-matched evaluation and the actual DML."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_RACE_CONDITION
    dialects = ("tsql",)

    impact = (
        "Concurrent MERGE statements can both evaluate NOT MATCHED and attempt "
        "INSERT, causing duplicate key errors. Or both evaluate MATCHED and "
        "overwrite each other's updates."
    )
    fix_guidance = (
        "Add WITH (HOLDLOCK) to the MERGE target: "
        "MERGE INTO target WITH (HOLDLOCK) USING ... "
        "Or wrap in SERIALIZABLE transaction."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if not self._has_pattern(query.raw, r"\bMERGE\b"):
            return []
        raw_upper = query.raw.upper()
        if "HOLDLOCK" in raw_upper or "SERIALIZABLE" in raw_upper:
            return []
        return [
            self.create_issue(
                query=query,
                message="MERGE without HOLDLOCK — concurrent execution may cause race conditions.",
                snippet=query.raw[:80],
            )
        ]
