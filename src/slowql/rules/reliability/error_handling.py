"""
Reliability Error handling rules.
"""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'ExceptionSwallowedRule',
    'LongTransactionWithoutSavepointRule',
]


class ExceptionSwallowedRule(PatternRule):
    """Detects exception handling blocks that swallow errors silently."""

    id = "REL-ERR-001"
    name = "Swallowed Exception Pattern"
    description = (
        "Detects exception handling blocks that swallow errors silently: WHEN OTHERS "
        "THEN NULL (Oracle), EXCEPTION WHEN OTHERS THEN (PL/pgSQL with no RAISE), "
        "and empty CATCH blocks in T-SQL. Swallowed exceptions hide data integrity "
        "failures and make debugging impossible."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_ERROR_HANDLING

    pattern = r"\bWHEN\s+OTHERS\s+THEN\s+NULL\b"
    message_template = "Exception handler may be swallowing errors silently: {match}"

    impact = (
        "Silent exception swallowing means failed operations appear to succeed. Data "
        "integrity violations, constraint failures, and deadlocks go undetected, "
        "leading to corrupted application state."
    )
    fix_guidance = (
        "Always re-raise or log exceptions. In Oracle PL/SQL use RAISE or "
        "RAISE_APPLICATION_ERROR. In PostgreSQL use RAISE EXCEPTION. In T-SQL use "
        "THROW or RAISERROR. Never use WHEN OTHERS THEN NULL in production code."
    )


class LongTransactionWithoutSavepointRule(PatternRule):
    """Detects SAVEPOINT usage for review in long transactions."""

    id = "REL-REC-001"
    name = "Missing Savepoint in Long Transaction"
    description = (
        "Detects long multi-statement transactions (containing 3 or more DML "
        "operations: INSERT, UPDATE, DELETE) without a SAVEPOINT. Long transactions "
        "without savepoints cannot be partially rolled back, forcing a full rollback "
        "on any error."
    )
    severity = Severity.INFO
    dimension = Dimension.RELIABILITY
    category = Category.REL_RECOVERY

    pattern = r"\bSAVEPOINT\b"
    message_template = "Long transaction detected — consider using SAVEPOINTs for partial recovery: {match}"
    impact = (
        "A failure in step 10 of a 10-step transaction forces rollback of all "
        "previous steps. Savepoints allow partial recovery and reduce re-work cost."
    )
    fix_guidance = (
        "Use SAVEPOINT after logically complete sub-operations within long "
        "transactions. Use ROLLBACK TO SAVEPOINT to recover from partial failures "
        "without rolling back the entire transaction."
    )
