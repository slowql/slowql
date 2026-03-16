"""DuckDB-specific performance rules."""
from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "DuckDBCopyWithoutFormatRule",
    "DuckDBLargeInListRule",
]


class DuckDBCopyWithoutFormatRule(PatternRule):
    """Detects COPY without explicit FORMAT in DuckDB."""

    id = "PERF-DUCK-001"
    name = "COPY Without FORMAT Specification"
    description = (
        "DuckDB's COPY command infers format from file extension, but "
        "explicit FORMAT specification avoids ambiguity and ensures "
        "correct parsing especially for extensionless paths or URLs."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("duckdb",)

    pattern = r"\bCOPY\b(?!.*\bFORMAT\b)"
    message_template = "COPY without explicit FORMAT — may cause incorrect parsing: {match}"

    impact = (
        "Without FORMAT, DuckDB guesses from the file extension. For "
        "URLs, pipes, or extensionless files this can silently fail."
    )
    fix_guidance = (
        "Add FORMAT explicitly: COPY t FROM 'file.csv' (FORMAT CSV). "
        "Supported: CSV, PARQUET, JSON."
    )


class DuckDBLargeInListRule(PatternRule):
    """Detects large IN lists in DuckDB where VALUES would be faster."""

    id = "PERF-DUCK-002"
    name = "Large IN List — Use VALUES Table"
    description = (
        "Large IN (...) lists in DuckDB are slower than using a VALUES "
        "table expression with a JOIN. DuckDB optimizes VALUES as a "
        "scan operator."
    )
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY
    dialects = ("duckdb",)

    pattern = r"\bIN\s*\(\s*(?:[^()]*,\s*){9,}"
    message_template = "Large IN list detected — consider VALUES table expression for performance: {match}"

    impact = (
        "Large IN lists are evaluated as repeated OR conditions. A VALUES "
        "table with a semi-join is more efficient for DuckDB's vectorized engine."
    )
    fix_guidance = (
        "Replace IN (1,2,...,100) with: "
        "JOIN (VALUES (1),(2),...,(100)) AS v(id) USING (id)."
    )
