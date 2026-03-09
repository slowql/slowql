"""
Quality Style rules.
"""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'CommentedCodeRule',
    'MissingAliasRule',
    'SelectWithoutFromRule',
    'WildcardInColumnListRule',
]


class SelectWithoutFromRule(PatternRule):
    """Detects SELECT statements used as constants without FROM — often a sign of poor quality."""

    id = "QUAL-STYLE-001"
    name = "SELECT Without FROM Clause"
    description = (
        "Detects SELECT statements that compute constant expressions without a "
        "FROM clause (e.g., SELECT 1, SELECT NOW(), SELECT 'value'). While valid "
        "in some databases, this pattern is often used in test code or leftover "
        "debug statements that should not reach production."
    )
    severity = Severity.INFO
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY

    pattern = r"^\s*SELECT\s+.+(?<!\bFROM\b.+)$"
    message_template = "SELECT without FROM detected — verify this is intentional: {match}"

    impact = (
        "Constant SELECT statements in application queries may indicate debug "
        "code left in production, test artifacts, or incomplete query construction."
    )
    fix_guidance = (
        "Remove debug SELECT statements before deployment. If the constant "
        "expression is needed, use database-specific syntax like SELECT 1 FROM "
        "DUAL (Oracle) or ensure the intent is documented."
    )


class WildcardInColumnListRule(PatternRule):
    """Detects SELECT * usage — already covered by SelectStarRule, this focuses on subqueries."""

    id = "QUAL-STYLE-002"
    name = "Wildcard in EXISTS Subquery"
    description = (
        "Detects SELECT * inside EXISTS subqueries. While functionally equivalent "
        "to SELECT 1 in most databases, SELECT * in EXISTS causes the query planner "
        "to potentially enumerate columns unnecessarily and signals poor query craftsmanship."
    )
    severity = Severity.INFO
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY

    pattern = r"\bEXISTS\s*\(\s*SELECT\s+\*"
    message_template = "SELECT * inside EXISTS subquery — use SELECT 1 instead: {match}"

    impact = (
        "SELECT * in EXISTS subqueries may prevent optimizer shortcuts in some "
        "databases and increases the surface area for column-level permission errors."
    )
    fix_guidance = (
        "Replace 'EXISTS (SELECT * FROM ...)' with 'EXISTS (SELECT 1 FROM ...)'. "
        "SELECT 1 clearly signals intent and is universally optimized."
    )


class MissingAliasRule(PatternRule):
    """Detects subqueries in FROM without an alias."""

    id = "QUAL-STYLE-003"
    name = "Subquery Missing Alias"
    description = (
        "Detects subqueries in FROM clauses that are not given an alias. "
        "Unaliased subqueries are rejected by most databases (MySQL, PostgreSQL) "
        "and always indicate incomplete or draft query construction."
    )
    severity = Severity.HIGH
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY

    pattern = r"\bFROM\s*\(\s*SELECT\b[^)]+\)\s*WHERE\b"
    message_template = "Subquery in FROM without alias detected — add an alias: {match}"

    impact = (
        "Unaliased subqueries cause syntax errors in PostgreSQL and MySQL. "
        "Even where accepted, they make the query unreadable and unreferenceable "
        "in outer query clauses."
    )
    fix_guidance = (
        "Add an alias after the closing parenthesis: FROM (SELECT ...) AS subquery_name. "
        "Choose a descriptive alias that reflects the subquery's purpose."
    )


class CommentedCodeRule(PatternRule):
    """Detects large blocks of commented-out SQL code."""

    id = "QUAL-STYLE-004"
    name = "Commented-Out SQL Code"
    description = (
        "Detects inline SQL comments that appear to contain commented-out query "
        "fragments (SELECT, INSERT, UPDATE, DELETE following -- or inside /* */). "
        "Commented-out code is a code quality smell indicating dead code that "
        "should be removed or tracked in version control."
    )
    severity = Severity.INFO
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY

    pattern = (
        r"--\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b"
        r"|/\*.*?(SELECT|INSERT|UPDATE|DELETE)\b.*?\*/"
    )
    message_template = "Commented-out SQL code detected — remove dead code or track in version control: {match}"

    impact = (
        "Commented-out code creates confusion about query intent, may hide "
        "dangerous statements, and bloats query logs."
    )
    fix_guidance = (
        "Remove commented-out SQL fragments before deploying queries. Use "
        "version control to track historical query variants. If the code may "
        "be needed, move it to a migration or script file with context."
    )
