"""
Reliability Transactions rules.
"""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "AutocommitDisabledRule",
    "EmptyTransactionRule",
    "MissingRollbackRule",
]


class MissingRollbackRule(PatternRule):
    """Detects BEGIN/START TRANSACTION blocks for rollback review."""

    id = "REL-TXN-001"
    name = "Missing Transaction Rollback Handler"
    description = (
        "Detects BEGIN/START TRANSACTION blocks that have a COMMIT but no ROLLBACK, "
        "indicating missing error handling. Transactions without ROLLBACK leave the "
        "database in an inconsistent state if an error occurs mid-transaction."
    )
    severity = Severity.INFO
    dimension = Dimension.RELIABILITY
    category = Category.REL_TRANSACTION

    pattern = r"\b(BEGIN|START\s+TRANSACTION)\b"
    message_template = "Transaction opened — verify ROLLBACK handler exists: {match}"

    impact = (
        "Without ROLLBACK, a failed transaction may partially commit changes, leaving "
        "data in an inconsistent state. This is especially dangerous for multi-step "
        "operations like financial transfers."
    )
    fix_guidance = (
        "Always pair BEGIN/COMMIT with a ROLLBACK in error handling. Use savepoints "
        "for partial rollbacks in complex transactions. In application code, use "
        "try/catch/finally patterns to ensure ROLLBACK on exception."
    )


class AutocommitDisabledRule(PatternRule):
    """Detects explicit disabling of autocommit mode."""

    id = "REL-TXN-002"
    name = "Autocommit Disable Detection"
    description = (
        "Detects explicit disabling of autocommit mode (SET autocommit = 0, "
        "SET IMPLICIT_TRANSACTIONS ON). When autocommit is disabled globally, every "
        "statement starts an implicit transaction that must be manually committed or "
        "rolled back, which can cause long-running locks and accidental data loss on "
        "connection drop."
    )
    severity = Severity.LOW
    dimension = Dimension.RELIABILITY
    category = Category.REL_TRANSACTION

    pattern = (
        r"\bSET\s+autocommit\s*=\s*0\b"
        r"|\bSET\s+IMPLICIT_TRANSACTIONS\s+ON\b"
    )
    message_template = "Autocommit disabled — risk of silent rollback on connection drop: {match}"

    impact = (
        "Disabling autocommit causes uncommitted changes to be silently rolled back "
        "on connection drop or application crash, leading to data loss. Long-running "
        "implicit transactions hold locks and degrade concurrency."
    )
    fix_guidance = (
        "Use explicit BEGIN/COMMIT blocks instead of disabling autocommit globally. "
        "If autocommit must be disabled, ensure every code path has explicit COMMIT "
        "or ROLLBACK. Monitor for long-running transactions via pg_stat_activity or "
        "information_schema.innodb_trx."
    )


class EmptyTransactionRule(PatternRule):
    """Detects BEGIN/COMMIT with no DML statements between them."""

    id = "REL-TXN-003"
    name = "Empty Transaction Block"
    description = (
        "A BEGIN...COMMIT block without any DML (INSERT, UPDATE, DELETE, "
        "SELECT) between them acquires and releases a transaction lock for "
        "no purpose. This is usually a code generation bug or copy-paste error."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_TRANSACTION
    dialects = ()

    pattern = r"\b(?:BEGIN|START\s+TRANSACTION)\s*;\s*(?:COMMIT|END)\b"
    message_template = "Empty transaction block detected — no DML between BEGIN and COMMIT: {match}"

    impact = (
        "Empty transactions acquire locks, write to WAL/transaction log, "
        "and consume connection slots for no purpose. In high-concurrency "
        "systems this adds unnecessary contention."
    )
    fix_guidance = (
        "Remove the empty BEGIN...COMMIT block, or add the intended DML "
        "statements between them."
    )
