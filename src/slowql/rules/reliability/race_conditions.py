from __future__ import annotations

"""
Reliability Race conditions rules.
"""

from typing import Any


from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'ReadModifyWriteLockingRule',
    'TOCTOUPatternRule',
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
    message_template = "Potential TOCTOU race condition detected: IF EXISTS check followed by modification."

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
