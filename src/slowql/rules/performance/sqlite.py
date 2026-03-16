"""SQLite-specific performance rules."""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "LikeWithoutCollateNocaseRule",
    "SqliteAutoIncrementRule",
    "SqliteWalModeRule",
]


class SqliteWalModeRule(PatternRule):
    """Detects SQLite usage without WAL mode hint."""

    id = "PERF-SQLITE-001"
    name = "Consider WAL Mode for Concurrent Access"
    description = (
        "SQLite defaults to journal_mode=DELETE which locks the entire "
        "database on writes. WAL (Write-Ahead Logging) mode allows "
        "concurrent readers during writes."
    )
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK
    dialects = ("sqlite",)

    pattern = r"\bPRAGMA\s+journal_mode\s*=\s*(?!wal\b)\w+"
    message_template = "Non-WAL journal mode detected — consider WAL for concurrency: {match}"

    impact = (
        "Without WAL mode, any write operation locks the entire database "
        "file, blocking all concurrent readers and writers."
    )
    fix_guidance = (
        "Set PRAGMA journal_mode=WAL for concurrent read/write access. "
        "Note: WAL mode is persistent and only needs to be set once."
    )


class LikeWithoutCollateNocaseRule(PatternRule):
    """Detects LIKE on columns without COLLATE NOCASE in SQLite."""

    id = "PERF-SQLITE-002"
    name = "LIKE Without COLLATE NOCASE"
    description = (
        "SQLite's LIKE operator is case-insensitive for ASCII by default, "
        "but indexes are case-sensitive. Using COLLATE NOCASE on the column "
        "definition allows indexes to be used with LIKE."
    )
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX
    dialects = ("sqlite",)

    pattern = r"\bLIKE\s+'[^']*'"
    message_template = "LIKE query detected — ensure column has COLLATE NOCASE for index usage: {match}"

    impact = (
        "Without COLLATE NOCASE on the column, LIKE queries cannot use "
        "indexes and fall back to full table scan."
    )
    fix_guidance = (
        "Define columns with COLLATE NOCASE: CREATE TABLE t (name TEXT "
        "COLLATE NOCASE). Or create an index with COLLATE NOCASE."
    )


class SqliteAutoIncrementRule(PatternRule):
    """Detects AUTOINCREMENT usage in SQLite which adds overhead."""

    id = "QUAL-SQLITE-001"
    name = "AUTOINCREMENT Overhead in SQLite"
    description = (
        "SQLite's AUTOINCREMENT keyword adds CPU overhead by maintaining "
        "the sqlite_sequence table. Plain INTEGER PRIMARY KEY already "
        "auto-generates unique rowids without this overhead."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_SCHEMA_DESIGN
    dialects = ("sqlite",)

    pattern = r"\bAUTOINCREMENT\b"
    message_template = "AUTOINCREMENT adds overhead — INTEGER PRIMARY KEY auto-generates IDs: {match}"

    impact = (
        "AUTOINCREMENT prevents rowid reuse and requires extra reads/writes "
        "to the sqlite_sequence table on every INSERT."
    )
    fix_guidance = (
        "Use INTEGER PRIMARY KEY without AUTOINCREMENT. SQLite guarantees "
        "unique monotonically increasing rowids without it. AUTOINCREMENT "
        "only guarantees never-reused IDs, which is rarely needed."
    )
