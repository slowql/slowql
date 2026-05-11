# slowql/src/slowql/core/context.py
"""
Source context classification for SlowQL.

Determines the role of a SQL file/query (migration, test, seed, application, etc.)
and provides context-aware rule filtering to eliminate false positives.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slowql.core.models import Issue

# ---------------------------------------------------------------------------
# Context types
# ---------------------------------------------------------------------------

MIGRATION = "migration"
APPLICATION = "application"
TEST = "test"
SEED = "seed"
DDL_SCHEMA = "ddl_schema"
VIEW_DEF = "view_definition"
STORED_PROC = "stored_procedure"
DBT_MODEL = "dbt_model"
ADHOC = "adhoc"

# ---------------------------------------------------------------------------
# Path-based classification patterns
# ---------------------------------------------------------------------------

_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Migration frameworks (ordered by specificity)
    (re.compile(r"(?:^|/)alembic/versions/", re.I), MIGRATION),
    (re.compile(r"(?:^|/)alembic/", re.I), MIGRATION),
    (re.compile(r"(?:^|/)migrations?/", re.I), MIGRATION),
    (re.compile(r"(?:^|/)db/migrate/", re.I), MIGRATION),
    (re.compile(r"(?:^|/)db/migrations/", re.I), MIGRATION),
    (re.compile(r"(?:^|/)flyway/", re.I), MIGRATION),
    (re.compile(r"(?:^|/)liquibase/", re.I), MIGRATION),
    (re.compile(r"(?:^|/)prisma/migrations/", re.I), MIGRATION),
    (re.compile(r"(?:^|/)src/main/resources/db/migration/", re.I), MIGRATION),
    # Tests
    (re.compile(r"(?:^|/)tests?/", re.I), TEST),
    (re.compile(r"(?:^|/)spec/", re.I), TEST),
    (re.compile(r"(?:^|/)__tests__/", re.I), TEST),
    (re.compile(r"(?:^|/).*test.*\.sql$", re.I), TEST),
    # Seeds/fixtures
    (re.compile(r"(?:^|/)seeds?/", re.I), SEED),
    (re.compile(r"(?:^|/)fixtures?/", re.I), SEED),
    # DDL/Schema
    (re.compile(r"(?:^|/)schema\.sql$", re.I), DDL_SCHEMA),
    (re.compile(r"(?:^|/)schema/", re.I), DDL_SCHEMA),
    (re.compile(r"(?:^|/)ddl/", re.I), DDL_SCHEMA),
    # dbt
    (re.compile(r"(?:^|/)models?/.*\.sql$", re.I), DBT_MODEL),
    (re.compile(r"(?:^|/)dbt_models?/", re.I), DBT_MODEL),
]

_CONTENT_MARKERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"revision\s*[:=].*\n.*down_revision", re.I | re.M), MIGRATION),
    (re.compile(r"class\s+\w*Migration\w*\s*\(", re.M), MIGRATION),
    (re.compile(r"def\s+(up|down)\s*\(", re.M), MIGRATION),
    (re.compile(r"--\s*(?:flyway|liquibase|prisma)", re.I), MIGRATION),
    (re.compile(r"--\s*migrate:\s*(up|down)", re.I), MIGRATION),
    (re.compile(r"\{\{\s*ref\s*\(", re.M), DBT_MODEL),
    (re.compile(r"\{\%\s*(config|materialization)", re.M), DBT_MODEL),
]

_APP_EXTENSIONS = frozenset(
    {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".kt", ".cs"}
)

# ---------------------------------------------------------------------------
# Context suppression rules
# ---------------------------------------------------------------------------
# Rules suppressed per context. These produce false positives because the
# pattern is intentional/acceptable in the given context.
# ---------------------------------------------------------------------------

_CONTEXT_SUPPRESSED: dict[str, frozenset[str]] = {
    MIGRATION: frozenset({
        "PERF-SCAN-001",   # SELECT * is fine in migrations
        "PERF-SCAN-002",   # UPDATE/DELETE without WHERE is fine in migrations
        "PERF-SCAN-005",   # DISTINCT in migrations is fine
        "QUAL-STYLE-001",  # Style rules not relevant in migrations
        "QUAL-STYLE-002",  # Same
        "QUAL-NULL-001",   # NULL comparisons fine in migrations
        "QUAL-NULL-002",   # Same
    }),
    TEST: frozenset({
        "PERF-SCAN-001",   # SELECT * fine in tests
        "PERF-SCAN-002",   # Missing WHERE fine in tests
        "PERF-SCAN-005",   # DISTINCT fine in tests
        "QUAL-STYLE-001",  # Style not relevant in tests
        "QUAL-STYLE-002",  # Same
    }),
    SEED: frozenset({
        "PERF-SCAN-001",   # SELECT * fine in seeds
        "PERF-SCAN-002",   # Missing WHERE fine in seeds
        "QUAL-STYLE-001",  # Style not relevant in seeds
    }),
    DDL_SCHEMA: frozenset({
        "PERF-SCAN-001",   # SELECT * in schema files is fine
    }),
}

# Prefix-based suppression: if a context suppresses a prefix, all rules with
# that prefix are suppressed. Avoids listing every numbered variant.
_CONTEXT_SUPPRESSED_PREFIXES: dict[str, frozenset[str]] = {
    MIGRATION: frozenset({"PERF-IDX-", "SCHEMA-IDX-"}),
    TEST: frozenset({"PERF-IDX-"}),
    SEED: frozenset({"PERF-IDX-"}),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_source(file_path: str | None, content: str = "") -> str:
    """
    Classify the source context of a SQL file.

    Args:
        file_path: Path to the file (may be None for raw SQL strings).
        content: File content (used for content-based heuristics).

    Returns:
        A context string (one of the module-level constants).
    """
    # 1. Path-based detection (highest confidence)
    if file_path:
        path_str = str(file_path).replace("\\", "/")
        fname = Path(file_path).name.lower()

        for pattern, ctx in _PATH_PATTERNS:
            if pattern.search(path_str) or pattern.search(fname):
                return ctx

        # Application code detection
        ext = Path(file_path).suffix.lower()
        if ext in _APP_EXTENSIONS:
            return APPLICATION

        # XML reaching here is likely MyBatis -> application
        if ext == ".xml":
            return APPLICATION

    # 2. Content-based detection
    if content:
        for pattern, ctx in _CONTENT_MARKERS:
            if pattern.search(content):
                return ctx

    # 3. Default
    return ADHOC


def filter_issues_by_context(
    issues: list[Issue], source_context: str
) -> list[Issue]:
    """
    Filter out issues that are suppressed by the source context.

    Args:
        issues: List of issues to filter.
        source_context: The classified source context string.

    Returns:
        Filtered list of issues (may be shorter than input).
    """
    if not source_context or source_context in (ADHOC, APPLICATION):
        return issues

    suppressed = _CONTEXT_SUPPRESSED.get(source_context, frozenset())
    suppressed_prefixes = _CONTEXT_SUPPRESSED_PREFIXES.get(
        source_context, frozenset()
    )

    if not suppressed and not suppressed_prefixes:
        return issues

    result: list[Issue] = []
    for issue in issues:
        # Exact match
        if issue.rule_id in suppressed:
            continue
        # Prefix match
        if suppressed_prefixes and any(
            issue.rule_id.startswith(p) for p in suppressed_prefixes
        ):
            continue
        result.append(issue)

    return result
