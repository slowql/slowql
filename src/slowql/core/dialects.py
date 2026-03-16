# src/slowql/core/dialects.py
"""
Dialect normalization utilities for SlowQL.

Provides canonical dialect names and alias resolution so that
rules, parsers, and config all agree on dialect identifiers.
"""

from __future__ import annotations

DIALECT_ALIASES: dict[str, str] = {
    "postgres": "postgresql",
    "pg": "postgresql",
    "mssql": "tsql",
    "sqlserver": "tsql",
    "sql_server": "tsql",
    "mariadb": "mysql",
    "bq": "bigquery",
    "sf": "snowflake",
}
"""Map of common shorthand names to their canonical dialect identifier."""

SUPPORTED_DIALECTS: frozenset[str] = frozenset(
    {
        "postgresql",
        "mysql",
        "tsql",
        "oracle",
        "sqlite",
        "bigquery",
        "snowflake",
        "redshift",
        "clickhouse",
        "duckdb",
        "presto",
        "trino",
        "spark",
        "databricks",
    }
)
"""Canonical set of dialect identifiers recognised by SlowQL."""


def normalize_dialect(dialect: str | None) -> str | None:
    """
    Normalise a dialect string to its canonical form.

    Args:
        dialect: Raw dialect string (e.g. ``"postgres"``, ``"mssql"``).

    Returns:
        Canonical dialect string, or ``None`` if *dialect* is ``None``
        or empty.

    Examples:
        >>> normalize_dialect("postgres")
        'postgresql'
        >>> normalize_dialect("MSSQL")
        'tsql'
        >>> normalize_dialect(None) is None
        True
    """
    if not dialect:
        return None
    key = dialect.lower().strip()
    return DIALECT_ALIASES.get(key, key)
