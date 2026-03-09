from __future__ import annotations

"""
Reliability Data safety rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'AlterTableDestructiveRule',
    'DropTableRule',
    'TruncateWithoutTransactionRule',
    'UnsafeWriteRule',
]


class UnsafeWriteRule(ASTRule):
    """Detects Critical Data Loss Risks (No WHERE)."""

    id = "REL-DATA-001"
    name = "Catastrophic Data Loss Risk"
    description = "Detects DELETE or UPDATE without WHERE clause."
    severity = Severity.CRITICAL
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if query.query_type not in ("DELETE", "UPDATE"):
            return []

        if not ast.find(exp.Where):
            return [
                self.create_issue(
                    query=query,
                    message=f"CRITICAL: {query.query_type} statement has no WHERE clause.",
                    snippet=query.raw,
                    severity=Severity.CRITICAL,
                    fix=Fix(
                        description="Add WHERE clause placeholder",
                        replacement=f"{query.raw.rstrip(';')} WHERE id = ...;",
                        is_safe=False,
                    ),
                    impact="Instant data loss of entire table content.",
                )
            ]
        return []


class DropTableRule(ASTRule):
    """Detects DROP TABLE statements."""

    id = "REL-DATA-004"
    name = "Destructive Schema Change (DROP)"
    description = "Detects DROP TABLE statements in code."
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if isinstance(ast, exp.Drop):
            return [
                self.create_issue(
                    query=query,
                    message="DROP statement detected.",
                    snippet=query.raw,
                    impact="Irreversible schema and data destruction. Ensure this is a migration "
                    "script.",
                )
            ]
        return []


class TruncateWithoutTransactionRule(PatternRule):
    """Detects TRUNCATE TABLE statements outside of an explicit transaction context."""

    id = "REL-DATA-002"
    name = "Truncate Without Transaction"
    description = (
        "Detects TRUNCATE TABLE statements outside of an explicit transaction context. "
        "TRUNCATE is non-transactional in many databases (MySQL, older PostgreSQL) and "
        "cannot be rolled back. Even in databases where it is transactional, it is "
        "rarely wrapped in a transaction in application code."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY

    pattern = (
        r"\bTRUNCATE\s+TABLE\b"
        r"|\bTRUNCATE\b(?!\s*--)"
    )
    message_template = "TRUNCATE TABLE detected outside explicit transaction: {match}"

    impact = (
        "TRUNCATE removes all rows instantly with no row-by-row logging, making "
        "recovery impossible without a backup in non-transactional databases."
    )
    fix_guidance = (
        "Wrap TRUNCATE in an explicit BEGIN/START TRANSACTION block with a subsequent "
        "COMMIT only after verification. Prefer DELETE with WHERE for recoverable "
        "operations. Use TRUNCATE only in controlled migration scripts."
    )


class AlterTableDestructiveRule(PatternRule):
    """Detects destructive ALTER TABLE operations."""

    id = "REL-DATA-003"
    name = "ALTER TABLE Without Backup Signal"
    description = (
        "Detects destructive ALTER TABLE operations: DROP COLUMN, MODIFY COLUMN "
        "(type change), and RENAME COLUMN. These operations can cause irreversible "
        "data loss or application breakage if not coordinated with application "
        "deployments."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY

    pattern = (
        r"\bALTER\s+TABLE\b.+\bDROP\s+COLUMN\b"
        r"|\bALTER\s+TABLE\b.+\bMODIFY\s+COLUMN\b"
        r"|\bALTER\s+TABLE\b.+\bRENAME\s+COLUMN\b"
        r"|\bALTER\s+TABLE\b.+\bCHANGE\s+COLUMN\b"
    )
    message_template = "Destructive ALTER TABLE operation detected: {match}"

    impact = (
        "DROP COLUMN permanently destroys column data. MODIFY COLUMN can silently "
        "truncate data if the new type is narrower. RENAME COLUMN breaks all "
        "application queries referencing the old name."
    )
    fix_guidance = (
        "Always take a full backup before destructive ALTER operations. Use "
        "expand-contract pattern for zero-downtime schema changes: add new column, "
        "migrate data, update application, then drop old column. Test in staging first."
    )
