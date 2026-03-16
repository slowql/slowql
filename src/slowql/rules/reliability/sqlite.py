"""SQLite-specific reliability rules."""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "SqliteDropColumnRule",
]


class SqliteDropColumnRule(PatternRule):
    """Detects ALTER TABLE DROP COLUMN which has limited support in SQLite."""

    id = "REL-SQLITE-001"
    name = "ALTER TABLE DROP COLUMN (SQLite Limitation)"
    description = (
        "ALTER TABLE DROP COLUMN was only added in SQLite 3.35.0 (2021). "
        "Older versions will error. Even in 3.35+ it has restrictions: "
        "cannot drop PRIMARY KEY, UNIQUE, or columns referenced by indexes."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("sqlite",)

    pattern = r"\bALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN\b"
    message_template = "ALTER TABLE DROP COLUMN — limited SQLite support (3.35+): {match}"

    impact = (
        "On SQLite < 3.35.0 this statement fails entirely. On 3.35+ it "
        "cannot drop primary key columns, unique columns, or columns "
        "referenced by indexes or foreign keys."
    )
    fix_guidance = (
        "For broad compatibility, use the 12-step ALTER TABLE process: "
        "CREATE new table, INSERT from old, DROP old, RENAME new. "
        "See https://www.sqlite.org/lang_altertable.html"
    )
