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
    # dbt (must come before test filename pattern so models/test.sql → dbt_model)
    (re.compile(r"(?:^|/)models?/.*\.sql$", re.I), DBT_MODEL),
    (re.compile(r"(?:^|/)dbt_models?/", re.I), DBT_MODEL),
    # Tests (directory-based, more specific)
    (re.compile(r"(?:^|/)tests?/", re.I), TEST),
    (re.compile(r"(?:^|/)spec/", re.I), TEST),
    (re.compile(r"(?:^|/)__tests__/", re.I), TEST),
    # Tests (filename-based, less specific — must come after dbt)
    (re.compile(r"(?:^|/)[^/]*test[^/]*\.sql$", re.I), TEST),
    # Seeds/fixtures
    (re.compile(r"(?:^|/)seeds?/", re.I), SEED),
    (re.compile(r"(?:^|/)fixtures?/", re.I), SEED),
    # DDL/Schema
    (re.compile(r"(?:^|/)schema\.sql$", re.I), DDL_SCHEMA),
    (re.compile(r"(?:^|/)schema/", re.I), DDL_SCHEMA),
    (re.compile(r"(?:^|/)ddl/", re.I), DDL_SCHEMA),
    # Application code (must come last - catches anything under src/)
    (re.compile(r"(?:^|/)src/", re.I), APPLICATION),
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
# Context allowlist rules
# ---------------------------------------------------------------------------
# For non-production contexts, only rules with allowed prefixes pass through.
# Production contexts (APPLICATION, ADHOC, DBT_MODEL, VIEW_DEF, STORED_PROC)
# get full analysis with no filtering.
# ---------------------------------------------------------------------------

_CONTEXT_ALLOWED_PREFIXES: dict[str, frozenset[str]] = {
    MIGRATION: frozenset({"SEC-", "REL-"}),
    TEST: frozenset({"SEC-", "REL-"}),
    SEED: frozenset({"SEC-", "REL-"}),
    DDL_SCHEMA: frozenset({"SEC-", "REL-", "COMP-"}),
}

# Per-context deny list: rules that are false positives even though their
# prefix is allowed (or for production contexts where no allowlist applies).
_CONTEXT_DENIED_RULES: dict[str, frozenset[str]] = {
    # Migration data is developer-controlled, not user input
    MIGRATION: frozenset({"SEC-INJ-005"}),
    # Test cleanup is intentional; test queries don't need tenant scoping
    TEST: frozenset({"REL-FK-002", "REL-DEAD-002", "SEC-AUTHZ-003"}),
    # Seed data is developer-controlled, not user input
    SEED: frozenset({"SEC-INJ-005"}),
    # dbt ref syntax only makes sense in dbt models
    APPLICATION: frozenset({"QUAL-DBT-001", "QUAL-DBT-002"}),
    ADHOC: frozenset({"QUAL-DBT-001", "QUAL-DBT-002"}),
    # dbt models don't use LIMIT
    DBT_MODEL: frozenset({"PERF-SCAN-003"}),
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
    Filter issues by source context using an allowlist.

    Production contexts (APPLICATION, ADHOC, DBT_MODEL, VIEW_DEF, STORED_PROC)
    receive full analysis with no filtering.

    Non-production contexts (MIGRATION, TEST, SEED, DDL_SCHEMA) only see
    rules with allowed prefixes (SEC-, REL- etc.).

    Args:
        issues: List of issues to filter.
        source_context: The classified source context string.

    Returns:
        Filtered list of issues (may be shorter than input).
    """
    # Step 1: Apply deny list (all contexts)
    denied = _CONTEXT_DENIED_RULES.get(source_context, frozenset())

    # Step 2: Production contexts pass through (minus denied)
    if not source_context or source_context in (
        ADHOC,
        APPLICATION,
        DBT_MODEL,
        VIEW_DEF,
        STORED_PROC,
    ):
        if not denied:
            return issues
        return [i for i in issues if i.rule_id not in denied]

    # Step 3: Non-production contexts use allowlist (minus denied)
    allowed = _CONTEXT_ALLOWED_PREFIXES.get(source_context)
    if not allowed:
        return [] if denied else issues

    return [
        issue
        for issue in issues
        if issue.rule_id not in denied
        and any(issue.rule_id.startswith(prefix) for prefix in allowed)
    ]
