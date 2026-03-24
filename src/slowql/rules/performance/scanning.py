"""
Performance Scanning rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    "BigQueryDistinctOnUnnestRule",
    "BigQueryRegexOnLargeTableRule",
    "CountStarWithoutWhereRule",
    "DistinctOnLargeSetRule",
    "ForceIndexHintMysqlRule",
    "MissingWhereRule",
    "NotInNullableSubqueryRule",
    "NotInSubqueryRule",
    "OrderByRandRule",
    "SelectForUpdateWithoutLimitMysqlRule",
    "SelectForUpdateWithoutNowaitPgRule",
    "SelectStarRule",
    "UnboundedSelectRule",
]


class SelectStarRule(ASTRule):
    """Detects usage of SELECT *."""

    id = "PERF-SCAN-001"
    name = "SELECT * Usage"
    description = "Detects wildcard selection (SELECT *) which causes unnecessary I/O."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    rationale = (
        "SELECT * retrieves all columns from a table, which often includes large "
        "text fields or unneeded metadata. This increases the amount of data "
        "transferred over the network and stored in application memory. "
        "Furthermore, using SELECT * prevented the database from using 'covering "
        "indexes' which could significantly speed up the query."
    )
    examples = (
        "SELECT * FROM users WHERE id = 1;",
        "SELECT id, username, email FROM users WHERE id = 1;",
    )


    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        if query.is_select:
            # Check for star in projections
            for expression in ast.find_all(exp.Star):
                # Ensure it's in the projection list (not count(*))
                parent = expression.parent
                if isinstance(parent, exp.Select):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="Avoid 'SELECT *'. Explicitly list required columns.",
                            snippet="SELECT *",
                            fix=Fix(
                                description="Replace * with specific column names",
                                replacement="SELECT col1, col2 ...",  # Placeholder logic
                                is_safe=False,  # Cannot safely auto-fix without schema
                            ),
                            impact="Increases network traffic, memory usage, and prevents covering "
                            "index usage.",
                        )
                    )
                    break  # Report once per query
        return issues


class MissingWhereRule(ASTRule):
    """Detects UPDATE/DELETE without WHERE (Performance aspect)."""

    # Note: This is also a Reliability rule, but handled here for large scan prevention

    id = "PERF-SCAN-002"
    name = "Unbounded Data Modification"
    description = "Detects UPDATE/DELETE statements affecting all rows."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if query.query_type not in ("UPDATE", "DELETE"):
            return []

        # Check for WHERE clause
        if not ast.find(exp.Where):
            return [
                self.create_issue(
                    query=query,
                    message=f"Unbounded {query.query_type} detected (missing WHERE).",
                    snippet=query.raw[:50],
                    impact="Will modify/delete ALL rows in the table, causing massive lock "
                    "contention and log growth.",
                )
            ]

        return []


class DistinctOnLargeSetRule(ASTRule):
    """Detects DISTINCT usage which causes sorting overhead."""

    id = "PERF-SCAN-005"
    name = "Expensive DISTINCT"
    description = "Detects DISTINCT usage which triggers expensive sort/hash operations."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if isinstance(ast, exp.Select) and ast.args.get("distinct"):
            return [
                self.create_issue(
                    query=query,
                    message="DISTINCT usage detected. Ensure this is necessary.",
                    snippet="SELECT DISTINCT ...",
                    impact="Requires sorting or hashing entire result set. Check if data model "
                    "allows duplicates.",
                )
            ]
        return []


class UnboundedSelectRule(ASTRule):
    """Detects SELECT without LIMIT on non-aggregated queries."""

    id = "PERF-SCAN-003"
    name = "Unbounded SELECT"
    description = "Detects SELECT statements with no LIMIT clause on non-aggregated queries."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    impact = "May return millions of rows, overwhelming application memory"
    fix_guidance = "Add LIMIT clause for paginated or exploratory queries"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if not query.is_select:
            return []

        has_group_by = ast.find(exp.Group) is not None
        has_limit = ast.find(exp.Limit) is not None
        has_agg = bool(
            list(ast.find_all(exp.Count))
            or list(ast.find_all(exp.Sum))
            or list(ast.find_all(exp.Avg))
        )

        if not has_group_by and not has_limit and not has_agg:
            return [
                self.create_issue(
                    query=query,
                    message="SELECT without LIMIT on non-aggregated query.",
                    snippet=query.raw[:80],
                )
            ]
        return []


class NotInSubqueryRule(ASTRule):
    """Detects NOT IN (...subquery...) pattern."""

    id = "PERF-SCAN-004"
    name = "NOT IN Subquery"
    description = "Detects NOT IN with subquery which can fail silently with NULLs."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

    impact = "NOT IN with subquery fails silently with NULLs and disables index usage"
    fix_guidance = "Rewrite as NOT EXISTS or LEFT JOIN ... WHERE col IS NULL"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for not_node in ast.find_all(exp.Not):
            in_node = not_node.find(exp.In)
            if in_node is not None:
                # Check if the IN contains a subquery
                if in_node.find(exp.Select):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="NOT IN with subquery detected. Vulnerable to NULL semantics.",
                            snippet=str(not_node),
                        )
                    )
                    break  # Report once per query
        return issues


class CountStarWithoutWhereRule(Rule):
    """Detects COUNT(*) without WHERE, suggesting pg_catalog.reltuples."""

    id = "PERF-PG-002"
    name = "Unfiltered COUNT(*) — Consider reltuples"
    description = "COUNT(*) without WHERE requires a full sequential scan in PostgreSQL."
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("postgresql",)
    impact = "COUNT(*) on a large table without WHERE scans every row."
    fix_guidance = "For approximate counts use: SELECT reltuples FROM pg_class WHERE relname = 'table'."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        raw_upper = query.raw.upper()
        if "COUNT(*)" not in raw_upper and "COUNT( *)" not in raw_upper:
            return []
        if "WHERE" in raw_upper:
            return []
        if query.query_type and query.query_type.upper() != "SELECT":
            return []
        return [self.create_issue(query=query, message="COUNT(*) without WHERE — consider pg_catalog.reltuples for approximate counts.", snippet=query.raw[:80])]


class NotInNullableSubqueryRule(Rule):
    """Detects NOT IN with subquery that may contain NULLs."""

    id = "PERF-PG-003"
    name = "NOT IN With Potentially NULLable Subquery"
    description = "NOT IN returns no rows if any value in the subquery result is NULL."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("postgresql",)
    impact = "A single NULL in the subquery result causes NOT IN to return zero rows."
    fix_guidance = "Replace NOT IN (SELECT ...) with NOT EXISTS (SELECT 1 FROM ... WHERE ...)."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        if not self._has_pattern(query.raw, r"\bNOT\s+IN\s*\(\s*SELECT\b"):
            return []
        return [self.create_issue(query=query, message="NOT IN with subquery may return wrong results if subquery contains NULLs — use NOT EXISTS.", snippet=query.raw[:80])]


class SelectForUpdateWithoutNowaitPgRule(Rule):
    """Detects SELECT FOR UPDATE without NOWAIT or SKIP LOCKED in PostgreSQL."""

    id = "PERF-PG-004"
    name = "SELECT FOR UPDATE Without NOWAIT/SKIP LOCKED (PG)"
    description = "SELECT FOR UPDATE without NOWAIT or SKIP LOCKED blocks indefinitely."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK
    dialects = ("postgresql",)
    impact = "Without NOWAIT, the query blocks until the lock is released."
    fix_guidance = "Add NOWAIT to fail immediately or SKIP LOCKED to skip locked rows."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        raw_upper = query.raw.upper()
        if "FOR UPDATE" not in raw_upper:
            return []
        if "NOWAIT" in raw_upper or "SKIP LOCKED" in raw_upper:
            return []
        return [self.create_issue(query=query, message="SELECT FOR UPDATE without NOWAIT or SKIP LOCKED — may block indefinitely.", snippet=query.raw[:80])]


class SelectForUpdateWithoutLimitMysqlRule(Rule):
    """Detects SELECT FOR UPDATE without LIMIT in MySQL."""

    id = "PERF-MYSQL-001"
    name = "SELECT FOR UPDATE Without LIMIT (MySQL)"
    description = "SELECT FOR UPDATE without LIMIT can escalate to table-level lock in InnoDB."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK
    dialects = ("mysql",)
    impact = "Locking too many rows blocks concurrent writes."
    fix_guidance = "Add LIMIT to restrict locked rows. Use indexed WHERE clause."

    def check(self, query: Query) -> list[Issue]:
        if not self._dialect_matches(query):
            return []
        raw_upper = query.raw.upper()
        if "FOR UPDATE" not in raw_upper:
            return []
        if "LIMIT" in raw_upper:
            return []
        return [self.create_issue(query=query, message="SELECT FOR UPDATE without LIMIT — may lock excessive rows in InnoDB.", snippet=query.raw[:80])]


class OrderByRandRule(PatternRule):
    """Detects ORDER BY RAND() which causes full table sort."""

    id = "PERF-MYSQL-002"
    name = "ORDER BY RAND() Full Table Sort"
    description = "ORDER BY RAND() generates a random value for every row then sorts all rows."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SORT
    dialects = ("mysql",)
    pattern = r"\bORDER\s+BY\s+RAND\s*\(\s*\)"
    message_template = "ORDER BY RAND() detected — full table sort regardless of LIMIT: {match}"
    impact = "On 1M rows, ORDER BY RAND() LIMIT 1 still reads and sorts all 1M rows."
    fix_guidance = "Use random offset subquery or maintain a sampling column."


class ForceIndexHintMysqlRule(PatternRule):
    """Detects FORCE INDEX / USE INDEX hints in MySQL."""

    id = "PERF-MYSQL-003"
    name = "FORCE INDEX / USE INDEX Hint"
    description = "FORCE INDEX overrides the optimizer. May become suboptimal as data changes."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_HINTS
    dialects = ("mysql",)
    pattern = r"\b(?:FORCE|USE|IGNORE)\s+INDEX\s*\("
    message_template = "Index hint detected — may become suboptimal as data changes: {match}"
    impact = "Forced indexes bypass the optimizer and may force worse plans over time."
    fix_guidance = "Remove index hints. Update statistics with ANALYZE TABLE instead."


class BigQueryDistinctOnUnnestRule(PatternRule):
    """Detects SELECT DISTINCT on UNNEST results in BigQuery."""

    id = "PERF-BQ-001"
    name = "SELECT DISTINCT on UNNEST"
    description = "DISTINCT on UNNEST forces a full shuffle of unnested data — expensive."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("bigquery",)
    pattern = r"\bSELECT\s+DISTINCT\b.*\bUNNEST\s*\("
    message_template = "DISTINCT on UNNEST — expensive full shuffle: {match}"
    impact = "UNNEST explodes arrays then DISTINCT shuffles all rows to deduplicate."
    fix_guidance = "Use ARRAY_AGG(DISTINCT ...) instead. Filter before UNNEST to reduce volume."


class BigQueryRegexOnLargeTableRule(PatternRule):
    """Detects REGEXP functions without WHERE filter in BigQuery."""

    id = "PERF-BQ-002"
    name = "REGEXP on Large Table Without Filter"
    description = "REGEXP functions are CPU-intensive and run on every row without a WHERE pre-filter."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN
    dialects = ("bigquery",)
    pattern = r"\bREGEXP_(?:CONTAINS|EXTRACT|REPLACE)\s*\("
    message_template = "REGEXP function detected — ensure WHERE clause limits scan: {match}"
    impact = "REGEXP on every row consumes slot time and increases cost."
    fix_guidance = "Pre-filter with LIKE or STARTS_WITH. Use partitioned/clustered tables."
