"""
Reliability Data safety rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    "AlterTableAddColumnVolatileDefaultRule",
    "AlterTableDestructiveRule",
    "AtAtIdentityRule",
    "BigQueryDmlWithoutWhereOnPartitionedRule",
    "CreateIndexWithoutConcurrentlyRule",
    "DropTableRule",
    "InsertIgnoreRule",
    "OracleAlterTableMoveWithoutRebuildRule",
    "ReplaceIntoRule",
    "TruncateInTryWithoutCatchRule",
    "TruncateWithoutTransactionRule",
    "UnsafeWriteRule",
    "Utf8InsteadOfUtf8mb4Rule",
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


class InsertIgnoreRule(PatternRule):
    """Detects INSERT IGNORE which silences errors."""

    id = "REL-MYSQL-001"
    name = "INSERT IGNORE Silences Errors"
    dialects = ("mysql",)
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    pattern = r"\bINSERT\s+IGNORE\b"
    message_template = "INSERT IGNORE detected — errors are silently suppressed: {match}"
    impact = (
        "INSERT IGNORE silently discards duplicate key errors, data truncation warnings, "
        "and constraint violations. Failed inserts are invisible — data loss goes undetected."
    )
    fix_guidance = (
        "Use INSERT ... ON DUPLICATE KEY UPDATE for intentional upserts. "
        "Use explicit duplicate checking for insert-only logic. "
        "Never use INSERT IGNORE where data integrity matters."
    )


class ReplaceIntoRule(PatternRule):
    """Detects REPLACE INTO which deletes and reinserts rows."""

    id = "REL-MYSQL-002"
    name = "REPLACE INTO Deletes and Reinserts"
    dialects = ("mysql",)
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    pattern = r"\bREPLACE\s+INTO\b"
    message_template = "REPLACE INTO detected — silently deletes and reinserts rows: {match}"
    impact = (
        "REPLACE INTO deletes the existing row and inserts a new one when a duplicate key "
        "is found. This resets AUTO_INCREMENT IDs, fires DELETE triggers unexpectedly, "
        "and breaks foreign key references silently."
    )
    fix_guidance = (
        "Use INSERT ... ON DUPLICATE KEY UPDATE instead. It updates only specified columns "
        "without deleting the row, preserving IDs, timestamps, and foreign key integrity."
    )


class Utf8InsteadOfUtf8mb4Rule(PatternRule):
    """Detects MySQL utf8 charset usage which only supports 3-byte characters."""

    id = "REL-MYSQL-003"
    name = "MySQL utf8 Instead of utf8mb4"
    description = (
        "MySQL's utf8 charset is an alias for utf8mb3 which only supports "
        "characters up to 3 bytes. This silently truncates 4-byte Unicode "
        "characters such as emoji and some CJK characters. Use utf8mb4 instead."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("mysql",)

    pattern = r"\b(?:CHARACTER\s+SET|CHARSET|DEFAULT\s+CHARSET)\s*=?\s*utf8\b(?!mb4)"
    message_template = "MySQL utf8 (3-byte) charset detected — use utf8mb4 for full Unicode: {match}"

    impact = (
        "Data containing 4-byte Unicode characters (emoji, some CJK, "
        "mathematical symbols) will be silently truncated or rejected, "
        "causing data loss."
    )
    fix_guidance = (
        "Replace CHARACTER SET utf8 with CHARACTER SET utf8mb4 and "
        "COLLATE utf8_general_ci with COLLATE utf8mb4_general_ci (or "
        "utf8mb4_unicode_ci). Update connection charset settings."
    )


class AtAtIdentityRule(PatternRule):
    """Detects @@IDENTITY usage which returns identity across scopes."""

    id = "REL-TSQL-001"
    name = "@@IDENTITY Instead of SCOPE_IDENTITY()"
    description = (
        "@@IDENTITY returns the last identity value generated in ANY scope "
        "on the current connection, including values generated by triggers. "
        "This can return the wrong value when triggers insert into tables "
        "with identity columns."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("tsql",)

    pattern = r"@@IDENTITY\b"
    message_template = "@@IDENTITY used — may return wrong value due to triggers: {match}"

    impact = (
        "If a trigger on the target table inserts into another table with an "
        "identity column, @@IDENTITY returns the trigger's identity value "
        "instead of the intended one, causing silent data corruption."
    )
    fix_guidance = (
        "Use SCOPE_IDENTITY() to get the last identity value generated in "
        "the current scope. For parallel inserts use OUTPUT clause."
    )


class CreateIndexWithoutConcurrentlyRule(PatternRule):
    """Detects CREATE INDEX without CONCURRENTLY on PostgreSQL."""

    id = "REL-PG-002"
    name = "CREATE INDEX Without CONCURRENTLY"
    description = "CREATE INDEX locks the table against writes. Use CONCURRENTLY to avoid this."
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("postgresql",)
    pattern = r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY\b)\w+"
    message_template = "CREATE INDEX without CONCURRENTLY — will lock table against writes: {match}"
    impact = "On large tables, CREATE INDEX can lock writes for minutes."
    fix_guidance = "Use CREATE INDEX CONCURRENTLY. Note: cannot run inside a transaction block."


class AlterTableAddColumnVolatileDefaultRule(Rule):
    """Detects ALTER TABLE ADD COLUMN with volatile DEFAULT in PostgreSQL."""

    id = "REL-PG-001"
    name = "ALTER TABLE ADD COLUMN With Volatile DEFAULT"
    description = "ALTER TABLE ADD COLUMN with volatile DEFAULT (now(), random()) rewrites the entire table."
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("postgresql",)
    impact = "A table rewrite on a large table locks it exclusively."
    fix_guidance = "Add column as NULLable first, backfill in batches, then add NOT NULL."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if not self._has_pattern(query.raw, r"\bALTER\s+TABLE\b.*\bADD\s+(?:COLUMN\s+)?\w+"):
            return []
        raw_upper = query.raw.upper()
        if "DEFAULT" not in raw_upper:
            return []
        for func in ["NOW()", "CURRENT_TIMESTAMP", "RANDOM()", "GEN_RANDOM_UUID()", "CLOCK_TIMESTAMP()"]:
            if func in raw_upper:
                return [self.create_issue(query=query, message="ALTER TABLE ADD COLUMN with volatile DEFAULT — may rewrite entire table.", snippet=query.raw[:100])]
        return []


class TruncateInTryWithoutCatchRule(Rule):
    """Detects TRUNCATE TABLE inside TRY without CATCH in T-SQL."""

    id = "REL-TSQL-003"
    name = "TRUNCATE in TRY Without CATCH"
    description = "TRUNCATE inside BEGIN TRY without BEGIN CATCH silently swallows errors."
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("tsql",)
    impact = "If TRUNCATE fails, the error is not caught and subsequent statements execute on stale data."
    fix_guidance = "Always pair BEGIN TRY with BEGIN CATCH. Use THROW to re-raise errors."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        raw_upper = query.raw.upper()
        if "TRUNCATE" not in raw_upper:
            return []
        if "BEGIN TRY" not in raw_upper:
            return []
        if "BEGIN CATCH" in raw_upper:
            return []
        return [self.create_issue(query=query, message="TRUNCATE inside BEGIN TRY without BEGIN CATCH — errors will be silently swallowed.", snippet=query.raw[:80])]


class OracleAlterTableMoveWithoutRebuildRule(Rule):
    """Detects ALTER TABLE MOVE without subsequent index rebuild in Oracle."""

    id = "REL-ORA-002"
    name = "ALTER TABLE MOVE Without REBUILD INDEX"
    description = "ALTER TABLE MOVE invalidates all indexes. They must be rebuilt afterwards."
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("oracle",)
    impact = "After MOVE, all indexes become UNUSABLE — queries error or fall back to full scans."
    fix_guidance = "Follow ALTER TABLE MOVE with ALTER INDEX ... REBUILD for every index."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if not self._has_pattern(query.raw, r"\bALTER\s+TABLE\b.*\bMOVE\b"):
            return []
        if "REBUILD" in query.raw.upper():
            return []
        return [self.create_issue(query=query, message="ALTER TABLE MOVE without REBUILD INDEX — all indexes become UNUSABLE.", snippet=query.raw[:80])]


class BigQueryDmlWithoutWhereOnPartitionedRule(Rule):
    """Detects DML without WHERE on BigQuery tables."""

    id = "REL-BQ-001"
    name = "DML Without WHERE on BigQuery"
    description = "UPDATE/DELETE without WHERE on BigQuery processes all partitions — expensive and irreversible."
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("bigquery",)
    impact = "DML on all partitions is expensive. BigQuery does not support ROLLBACK."
    fix_guidance = "Always include WHERE with partition filter: WHERE _PARTITIONDATE = '2024-01-01'."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if query.query_type not in ("UPDATE", "DELETE"):
            return []
        if "WHERE" in query.raw.upper():
            return []
        return [self.create_issue(query=query, message="DML without WHERE on BigQuery — will process all partitions.", snippet=query.raw[:80])]
