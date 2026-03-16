"""SQLite-specific reliability rules."""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "SqliteDropColumnRule",
    "SqliteForeignKeysOffRule",
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


class SqliteForeignKeysOffRule(PatternRule):
    """Detects PRAGMA foreign_keys = OFF in SQLite."""

    id = "REL-SQLITE-002"
    name = "PRAGMA foreign_keys = OFF"
    description = (
        "Disabling foreign key enforcement in SQLite allows orphan records "
        "and referential integrity violations. SQLite defaults to foreign "
        "keys OFF, so this pragma explicitly maintains that unsafe state."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_FOREIGN_KEY
    dialects = ("sqlite",)

    pattern = r"\bPRAGMA\s+foreign_keys\s*=\s*(?:OFF|0|false)\b"
    message_template = "PRAGMA foreign_keys = OFF — referential integrity disabled: {match}"

    impact = (
        "Without foreign key enforcement, INSERT and DELETE can create "
        "orphan records that violate data relationships. There is no "
        "automatic cleanup."
    )
    fix_guidance = (
        "Set PRAGMA foreign_keys = ON at connection startup. Note: this "
        "must be set per-connection, not per-database."
    )
