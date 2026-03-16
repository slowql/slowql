"""SQLite-specific security rules."""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "AttachDatabaseRule",
]


class AttachDatabaseRule(PatternRule):
    """Detects ATTACH DATABASE which can access arbitrary files in SQLite."""

    id = "SEC-SQLITE-001"
    name = "ATTACH DATABASE Arbitrary File Access"
    description = (
        "ATTACH DATABASE in SQLite opens an arbitrary file as a database. "
        "If the filename is user-controlled, an attacker can read or create "
        "files anywhere the process has access, including overwriting "
        "application databases or reading sensitive files."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE
    dialects = ("sqlite",)

    pattern = r"\bATTACH\s+(?:DATABASE\s+)?(?:'[^']*'|\"[^\"]*\"|\S+)\s+AS\b"
    message_template = "ATTACH DATABASE detected — arbitrary file access risk: {match}"

    impact = (
        "An attacker can read any file as a SQLite database or create new "
        "files. Combined with writeable paths, this enables code execution "
        "via crafted database files."
    )
    fix_guidance = (
        "Never allow user input in ATTACH DATABASE paths. Use "
        "sqlite3_limit(SQLITE_LIMIT_ATTACHED) to restrict. Consider "
        "SQLITE_DBCONFIG_ENABLE_ATTACH to disable entirely."
    )
