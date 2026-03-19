"""
Quality Style rules.
"""

from __future__ import annotations

import re
from typing import Any

from sqlglot import exp

from slowql.core.models import (
    Category,
    Dimension,
    Fix,
    FixConfidence,
    Issue,
    Query,
    RemediationMode,
    Severity,
)
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    "AnsiNullsOffRule",
    "ClickHouseOrderByWithoutLimitRule",
    "CommentedCodeRule",
    "InsertWithoutColumnListRule",
    "InsertWithoutColumnListRule",
    "MissingAliasRule",
    "PgDoBlockWithoutLanguageRule",
    "PgDoBlockWithoutLanguageRule",
    "RedshiftDiststyleAllRule",
    "RedshiftDiststyleAllRule",
    "SelectWithoutFromRule",
    "SnowflakeFlattenWithoutPathRule",
    "SnowflakeFlattenWithoutPathRule",
    "StraightJoinHintRule",
    "TsqlQuotedIdentifierOffRule",
    "TsqlQuotedIdentifierOffRule",
    "WildcardInColumnListRule",
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

    pattern = r"^\s*SELECT\b(?![\s\S]*\bFROM\b)[\s\S]+$"
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
    remediation_mode = RemediationMode.SAFE_APPLY

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

    def suggest_fix(self, query: Query) -> Fix | None:
        """
        Suggest a safe fix for SELECT * inside EXISTS subqueries.

        The fix targets only the exact inner SELECT * span inside EXISTS(...).
        """
        match = re.search(self.pattern, query.raw, re.IGNORECASE)
        if not match:
            return None

        segment = query.raw[match.start():]
        select_match = re.search(r"(?i)\bSELECT\s+\*", segment)
        if not select_match:
            return None

        span_start = match.start() + select_match.start()
        span_end = match.start() + select_match.end()

        return Fix(
            description="Replace SELECT * with SELECT 1 inside EXISTS subquery",
            original=query.raw[span_start:span_end],
            replacement="SELECT 1",
            confidence=FixConfidence.SAFE,
            rule_id=self.id,
            is_safe=True,
            start=span_start,
            end=span_end,
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
    message_template = (
        "Commented-out SQL code detected — remove dead code or track in version control: {match}"
    )

    impact = (
        "Commented-out code creates confusion about query intent, may hide "
        "dangerous statements, and bloats query logs."
    )
    fix_guidance = (
        "Remove commented-out SQL fragments before deploying queries. Use "
        "version control to track historical query variants. If the code may "
        "be needed, move it to a migration or script file with context."
    )


class StraightJoinHintRule(PatternRule):
    """Detects STRAIGHT_JOIN hint in MySQL."""

    id = "QUAL-MYSQL-002"
    name = "STRAIGHT_JOIN Hint"
    description = "STRAIGHT_JOIN forces MySQL to read tables in query order, overriding optimizer."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN
    dialects = ("mysql",)
    pattern = r"\bSTRAIGHT_JOIN\b"
    message_template = "STRAIGHT_JOIN hint detected — overrides optimizer join order: {match}"
    impact = "Forced join order may become suboptimal as data distribution changes."
    fix_guidance = "Remove STRAIGHT_JOIN. Update statistics with ANALYZE TABLE."


class AnsiNullsOffRule(PatternRule):
    """Detects SET ANSI_NULLS OFF in T-SQL."""

    id = "QUAL-TSQL-001"
    name = "SET ANSI_NULLS OFF"
    description = "SET ANSI_NULLS OFF enables deprecated non-standard NULL comparison behavior."
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN
    dialects = ("tsql",)
    pattern = r"\bSET\s+ANSI_NULLS\s+OFF\b"
    message_template = "SET ANSI_NULLS OFF detected — deprecated non-standard behavior: {match}"
    impact = "Code relying on ANSI_NULLS OFF will break when the setting is removed."
    fix_guidance = "Use IS NULL instead of = NULL. Remove SET ANSI_NULLS OFF."


    remediation_mode = RemediationMode.SAFE_APPLY

    def suggest_fix(self, query: Query) -> Fix | None:
        """Replace SET ANSI_NULLS OFF with SET ANSI_NULLS ON."""
        match = re.search(r"\bSET\s+ANSI_NULLS\s+OFF\b", query.raw, re.IGNORECASE)
        if not match:
            return None
        return Fix(
            description="Replace SET ANSI_NULLS OFF with ON",
            original=match.group(0),
            replacement="SET ANSI_NULLS ON",
            confidence=FixConfidence.SAFE,
            is_safe=True,
            rule_id=self.id,
        )


class PgDoBlockWithoutLanguageRule(PatternRule):
    """Detects DO $$ blocks without explicit LANGUAGE specification."""

    id = "QUAL-PG-001"
    name = "DO Block Without LANGUAGE"
    remediation_mode = RemediationMode.SAFE_APPLY
    description = (
        "PostgreSQL DO blocks should specify LANGUAGE explicitly. Without "
        "it, PostgreSQL defaults to plpgsql but this is implicit and "
        "reduces readability."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    dialects = ("postgresql",)

    pattern = r"\bDO\s+\$\$(?!.*\bLANGUAGE\b)"
    message_template = "DO block without LANGUAGE specification: {match}"

    impact = (
        "Implicit language defaults reduce code clarity and can cause "
        "errors if the default language changes or if plpgsql is not loaded."
    )
    fix_guidance = (
        "Add LANGUAGE plpgsql: DO $$ BEGIN ... END $$ LANGUAGE plpgsql;"
    )


    def suggest_fix(self, query: Query) -> Fix | None:
        """Append LANGUAGE plpgsql to DO $$ blocks."""
        # Match DO $$ ... $$ without LANGUAGE
        match = re.search(r"(\$\$\s*;?)\s*$", query.raw.rstrip(), re.IGNORECASE)
        if not match:
            return None
        # Verify LANGUAGE is not already present
        if re.search(r"\bLANGUAGE\b", query.raw, re.IGNORECASE):
            return None
        original = match.group(0)
        replacement = match.group(1) if match.group(1).endswith(";") else match.group(1) + " LANGUAGE plpgsql;"
        if match.group(1).endswith(";"):
            # Replace trailing ; with LANGUAGE plpgsql;
            replacement = match.group(1)[:-1] + " LANGUAGE plpgsql;"
        return Fix(
            description="Add explicit LANGUAGE plpgsql",
            original=original,
            replacement=replacement,
            confidence=FixConfidence.SAFE,
            is_safe=True,
            rule_id=self.id,
        )

class RedshiftDiststyleAllRule(PatternRule):
    """Detects DISTSTYLE ALL on potentially large tables in Redshift."""

    id = "QUAL-RS-001"
    name = "DISTSTYLE ALL on Large Table"
    description = (
        "DISTSTYLE ALL copies the entire table to every node. This is "
        "only appropriate for small dimension tables. On large tables "
        "it wastes storage and slows down writes."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_SCHEMA_DESIGN
    dialects = ("redshift",)

    pattern = r"\bDISTSTYLE\s+ALL\b"
    message_template = "DISTSTYLE ALL detected — entire table copied to every node: {match}"

    impact = (
        "Every INSERT, UPDATE, DELETE replicates to all nodes. For large "
        "tables this multiplies write time and storage by the cluster size."
    )
    fix_guidance = (
        "Use DISTSTYLE ALL only for small dimension tables (<1M rows). "
        "For large tables use DISTSTYLE KEY or DISTSTYLE EVEN."
    )


class ClickHouseOrderByWithoutLimitRule(Rule):
    """Detects ORDER BY without LIMIT on ClickHouse."""

    id = "QUAL-CH-001"
    name = "ORDER BY Without LIMIT on ClickHouse"
    description = (
        "ORDER BY without LIMIT on ClickHouse requires gathering and "
        "sorting all data on a single node. For distributed tables this "
        "causes massive memory usage."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN
    dialects = ("clickhouse",)

    impact = (
        "All data is gathered to one node for global sorting. This can "
        "exhaust memory and crash the query."
    )
    fix_guidance = (
        "Add LIMIT to bound results. Or use ORDER BY with LIMIT BY for "
        "top-N per group patterns."
    )

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        raw_upper = query.raw.upper()
        if "ORDER BY" not in raw_upper:
            return []
        if "LIMIT" in raw_upper:
            return []
        if query.query_type and query.query_type.upper() != "SELECT":
            return []
        return [self.create_issue(query=query, message="ORDER BY without LIMIT on ClickHouse — full sort on single node.", snippet=query.raw[:80])]


class SnowflakeFlattenWithoutPathRule(PatternRule):
    """Detects FLATTEN without explicit path in Snowflake."""

    id = "QUAL-SF-001"
    name = "FLATTEN Without Explicit Path"
    description = (
        "LATERAL FLATTEN without explicit path or input parameter relies "
        "on implicit column resolution, which can break if the schema "
        "changes."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    dialects = ("snowflake",)

    pattern = r"\bFLATTEN\s*\(\s*(?!.*\binput\b|.*\bpath\b)"
    message_template = "FLATTEN without explicit input/path — fragile implicit resolution: {match}"

    impact = (
        "Without explicit path, FLATTEN depends on column position which "
        "can silently produce wrong results after schema changes."
    )
    fix_guidance = (
        "Use explicit parameters: LATERAL FLATTEN(input => col, path => 'key')."
    )


class InsertWithoutColumnListRule(ASTRule):
    """Detects INSERT INTO table VALUES without explicit column list."""

    id = "QUAL-STYLE-005"
    name = "INSERT Without Column List"
    description = (
        "INSERT INTO table VALUES (...) without specifying columns depends "
        "on column order. If the table schema changes (column added, reordered), "
        "the INSERT silently inserts data into wrong columns or fails."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    dialects = ()

    impact = (
        "A schema change (ALTER TABLE ADD COLUMN) silently shifts all values "
        "one position, causing data corruption without any error."
    )
    fix_guidance = (
        "Always specify columns: INSERT INTO table (col1, col2) VALUES (v1, v2)."
    )

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Insert):
                # Check if column list is specified
                cols = node.args.get("columns")
                if not cols:
                    # Check it's a VALUES insert (not INSERT INTO ... SELECT)
                    values = node.find(exp.Values)
                    if values:
                        issues.append(self.create_issue(
                            query=query,
                            message="INSERT without column list — fragile if schema changes.",
                            snippet=query.raw[:80],
                        ))
        return issues


class TsqlQuotedIdentifierOffRule(PatternRule):
    """Detects SET QUOTED_IDENTIFIER OFF in T-SQL."""

    id = "QUAL-TSQL-002"
    name = "SET QUOTED_IDENTIFIER OFF"
    description = (
        "SET QUOTED_IDENTIFIER OFF allows double quotes to delimit strings "
        "instead of identifiers. This is non-standard, deprecated, and "
        "breaks indexed views, computed columns, and filtered indexes."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN
    dialects = ("tsql",)

    pattern = r"\bSET\s+QUOTED_IDENTIFIER\s+OFF\b"
    message_template = "SET QUOTED_IDENTIFIER OFF — deprecated, breaks indexes: {match}"

    impact = (
        "With QUOTED_IDENTIFIER OFF, indexed views and computed columns "
        "cannot be created or queried. This is deprecated and will be "
        "removed in a future SQL Server version."
    )
    fix_guidance = (
        "Remove SET QUOTED_IDENTIFIER OFF. Use single quotes for strings "
        "and double quotes or square brackets for identifiers."
    )

    remediation_mode = RemediationMode.SAFE_APPLY

    def suggest_fix(self, query: Query) -> Fix | None:
        """Replace SET QUOTED_IDENTIFIER OFF with SET QUOTED_IDENTIFIER ON."""
        match = re.search(r"\bSET\s+QUOTED_IDENTIFIER\s+OFF\b", query.raw, re.IGNORECASE)
        if not match:
            return None
        return Fix(
            description="Replace SET QUOTED_IDENTIFIER OFF with ON",
            original=match.group(0),
            replacement="SET QUOTED_IDENTIFIER ON",
            confidence=FixConfidence.SAFE,
            is_safe=True,
            rule_id=self.id,
        )
