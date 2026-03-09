"""
Performance Locking rules.
"""

from __future__ import annotations

from typing import Any

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'LongTransactionPatternRule',
    'MissingTransactionIsolationRule',
    'ReadUncommittedHintRule',
    'TableLockHintRule',
]


class TableLockHintRule(PatternRule):
    """Detects table-level lock hints that can cause severe blocking under concurrency."""

    id = "PERF-LOCK-001"
    name = "Table Lock Hint"
    description = "Detects table-level lock hints that can cause severe blocking under concurrency."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK

    pattern = r"\bWITH\s*\(\s*(TABLOCK|TABLOCKX|HOLDLOCK|XLOCK|PAGLOCK|ROWLOCK|UPDLOCK|SERIALIZABLE)\s*\)"
    message_template = "Extremely restrictive locking hint detected: {match}"

    impact = (
        "Table-level locks (TABLOCK, TABLOCKX) block ALL concurrent access to the table. "
        "Under load, this creates cascading waits that can freeze the entire application."
    )
    fix_guidance = "Remove table lock hints unless absolutely necessary. Use row-level locking (default behavior)."


class ReadUncommittedHintRule(PatternRule):
    """Detects NOLOCK or READ UNCOMMITTED hints that can return inconsistent data."""

    id = "PERF-LOCK-002"
    name = "NOLOCK / Read Uncommitted Hint"
    description = "Detects NOLOCK or READ UNCOMMITTED hints that can return inconsistent data."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK

    pattern = r"\bWITH\s*\(\s*(NOLOCK|READUNCOMMITTED)\s*\)|\bREAD\s+UNCOMMITTED\b|\bSET\s+TRANSACTION\s+ISOLATION\s+LEVEL\s+READ\s+UNCOMMITTED\b"
    message_template = "NOLOCK or READ UNCOMMITTED hint detected: {match}"

    impact = (
        "NOLOCK reads uncommitted data (dirty reads), can skip rows, read rows twice, "
        "or return phantom data. It's not 'faster' — it's 'wrong'."
    )
    fix_guidance = "Use READ COMMITTED SNAPSHOT ISOLATION (RCSI) for non-blocking reads without dirty reads."


class LongTransactionPatternRule(PatternRule):
    """Detects patterns indicating potentially long-running transactions that hold locks."""

    id = "PERF-LOCK-003"
    name = "Long Transaction Pattern"
    description = "Detects patterns indicating potentially long-running transactions that hold locks."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK

    pattern = r"\bBEGIN\s+(TRAN|TRANSACTION)\b[\s\S]{500,}?\b(COMMIT|ROLLBACK)\b"
    message_template = "Potentially long-running transaction detected (500+ characters)"

    impact = (
        "Long transactions hold locks for their entire duration, blocking other queries. "
        "A 10-second transaction holding a lock can queue up hundreds of waiting requests."
    )
    fix_guidance = "Keep transactions as short as possible. Do all preparation BEFORE BEGIN TRAN. Use optimistic concurrency."


class MissingTransactionIsolationRule(ASTRule):
    """Detects explicit transactions without isolation level specification."""

    id = "PERF-LOCK-004"
    name = "Missing Transaction Isolation Level"
    description = "Detects explicit transactions without isolation level specification, relying on default behavior."
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        query_upper = query.raw.upper()

        has_begin_tran = 'BEGIN TRAN' in query_upper or 'BEGIN TRANSACTION' in query_upper
        has_isolation = 'ISOLATION LEVEL' in query_upper

        if has_begin_tran and not has_isolation:
            issues.append(self.create_issue(
                query=query,
                message="Transaction without explicit isolation level - behavior depends on server defaults",
                snippet=query.raw[:100],
                impact=(
                    "Default isolation levels vary by database and configuration. Code that works in development "
                    "may behave differently in production, causing subtle bugs or blocking."
                ),
                fix=Fix(
                    description="Explicitly set isolation level: SET TRANSACTION ISOLATION LEVEL READ COMMITTED.",
                    replacement="",
                    is_safe=False,
                ),
            ))

        return issues
