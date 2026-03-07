# slowql/src/slowql/rules/catalog.py
"""
Catalog of built-in detection rules.

This module contains the definitions of all built-in rules for:
- Security (Injection, Sensitive Data)
- Performance (Index usage, Scans)
- Reliability (Data safety)
- Compliance (GDPR, PII)
- Quality (Best practices)

These rules are loaded by the RuleRegistry and used by their
respective Analyzers.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import (
    Category,
    Dimension,
    Fix,
    Issue,
    Query,
    Severity,
)
from slowql.rules.base import ASTRule, PatternRule, Rule

# =============================================================================
# 🔒 SECURITY RULES
# =============================================================================


class SQLInjectionRule(PatternRule):
    """Detects potential SQL injection via string concatenation."""

    id = "SEC-INJ-001"
    name = "Potential SQL Injection"
    description = "Detects string concatenation in SQL queries which may indicate SQL injection."
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r"(?i)(['\"]\s*\+\s*[a-zA-Z_]\w*)|([a-zA-Z_]\w*\s*\+\s*['\"])"
    message_template = (
        "Potential SQL injection detected: String concatenation with variable '{match}'."
    )

    impact = "Attackers can execute arbitrary SQL commands, accessing or destroying data."
    rationale = "Dynamic SQL construction using concatenation is the #1 vector for SQL injection."
    fix_guidance = "Use parameterized queries (prepared statements) instead of concatenation."
    references = ("https://owasp.org/www-community/attacks/SQL_Injection",)


class HardcodedPasswordRule(PatternRule):
    """Detects hardcoded passwords in queries."""

    id = "SEC-AUTH-001"
    name = "Hardcoded Password"
    description = "Detects plain-text passwords assigned in SQL queries."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r"(?i)(password|passwd|pwd|secret|token)\s*=\s*'[^']+'"
    message_template = "Hardcoded credential detected: {match}"

    impact = "Credentials exposed in source code or logs can be used by attackers."
    rationale = "Secrets should never be stored in plain text within code or queries."
    fix_guidance = "Use query parameters and secrets management."


class GrantAllRule(ASTRule):
    """Detects GRANT ALL permissions."""

    id = "SEC-AUTH-005"
    name = "Excessive Privileges (GRANT ALL)"
    description = "Detects GRANT ALL statements which violate least privilege."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        # SQLGlot parses GRANT specifically
        if isinstance(ast, exp.Grant):
            # Use getattr to safely access 'actions' without triggering static analysis errors
            raw_actions = getattr(ast, "actions", None) or []
            normalized_actions = []

            for action in raw_actions:
                # Handle Identifier/Var nodes vs raw strings if any
                if hasattr(action, "name"):
                    normalized_actions.append(action.name.upper())
                else:
                    normalized_actions.append(str(action).upper())

            if "ALL" in normalized_actions or "ALL PRIVILEGES" in normalized_actions:
                issues.append(
                    self.create_issue(
                        query=query,
                        message="GRANT ALL detected. Follow principle of least privilege.",
                        snippet=query.raw,
                        impact="Users receive administrative control, increasing blast radius of "
                        "compromise.",
                    )
                )

        return issues


# =============================================================================
# ⚡ PERFORMANCE RULES
# =============================================================================


class SelectStarRule(ASTRule):
    """Detects usage of SELECT *."""

    id = "PERF-SCAN-001"
    name = "SELECT * Usage"
    description = "Detects wildcard selection (SELECT *) which causes unnecessary I/O."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SCAN

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


class LeadingWildcardRule(PatternRule):
    """Detects leading wildcards in LIKE clauses."""

    id = "PERF-IDX-002"
    name = "Leading Wildcard Search"
    description = "Detects LIKE '%value' patterns which prevent index usage."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    pattern = r"(?i)\s+LIKE\s+['\"]%[^'\"]+['\"]"
    message_template = "Non-SARGable query: Leading wildcard in LIKE clause '{match}'."

    impact = "Forces a full table scan because B-Tree indexes cannot be traversed in reverse."
    fix_guidance = (
        "Use Full-Text Search (e.g., Elasticsearch, Postgres FTS) for substring searches."
    )


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


class FunctionOnIndexedColumnRule(ASTRule):
    """Detects functions wrapping columns in WHERE clause."""

    id = "PERF-IDX-001"
    name = "Function on Indexed Column"
    description = "Detects functions applied to columns in WHERE predicates (e.g. WHERE LOWER(email) = ...)."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    impact = "Prevents index usage, forces full table scan"
    fix_guidance = "Use functional indexes or rewrite predicate without wrapping function"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        where = ast.find(exp.Where)
        if where is None:
            return []

        for func in where.find_all(exp.Func):
            # Check if the function wraps a column reference
            if func.find(exp.Column):
                issues.append(
                    self.create_issue(
                        query=query,
                        message=f"Function '{type(func).__name__}' applied to column in WHERE clause prevents index usage.",
                        snippet=str(func),
                    )
                )
                break  # Report once per query
        return issues


class OrOnIndexedColumnsRule(PatternRule):
    """Detects OR conditions in WHERE clauses."""

    id = "PERF-IDX-004"
    name = "OR in WHERE Clause"
    description = "Detects OR conditions in WHERE clauses which can prevent index usage."
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    pattern = r"(?i)\bWHERE\b.+\bOR\b"
    message_template = "OR condition in WHERE clause detected: {match}"

    impact = "OR conditions can prevent index usage depending on the query planner"
    fix_guidance = "Consider rewriting as UNION ALL of two queries"


class DeepOffsetPaginationRule(PatternRule):
    """Detects OFFSET values over 1000."""

    id = "PERF-IDX-005"
    name = "Deep Offset Pagination"
    description = "Detects OFFSET values over 1000 which degrade pagination performance."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    pattern = r"(?i)\bOFFSET\s+([1-9]\d{3,})\b"
    message_template = "Deep pagination detected with large OFFSET: {match}"

    impact = "Database must scan and discard all rows before the offset"
    fix_guidance = "Use keyset/cursor pagination instead: WHERE id > last_seen_id LIMIT n"


class CartesianProductRule(ASTRule):
    """Detects CROSS JOIN usage."""

    id = "PERF-JOIN-001"
    name = "Cartesian Product (CROSS JOIN)"
    description = "Detects CROSS JOIN usage which produces a Cartesian product of rows."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_JOIN

    impact = "Produces row count = table1_rows * table2_rows, exponential cost"
    fix_guidance = "Add explicit JOIN condition or use INNER JOIN"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for join in ast.find_all(exp.Join):
            kind = join.args.get("kind")
            if kind and str(kind).upper() == "CROSS":
                issues.append(
                    self.create_issue(
                        query=query,
                        message="CROSS JOIN detected. This produces a Cartesian product.",
                        snippet=str(join),
                    )
                )
                break  # Report once per query
        return issues


class TooManyJoinsRule(ASTRule):
    """Detects queries with 5 or more JOINs."""

    id = "PERF-JOIN-002"
    name = "Excessive Joins"
    description = "Detects queries with 5 or more JOIN clauses."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_JOIN

    impact = "High join count increases query plan complexity and memory usage"
    fix_guidance = "Consider breaking into CTEs or denormalizing hot query paths"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        joins = list(ast.find_all(exp.Join))
        if len(joins) >= 5:
            return [
                self.create_issue(
                    query=query,
                    message=f"Query has {len(joins)} JOINs. Consider simplifying.",
                    snippet=query.raw[:80],
                )
            ]
        return []


class UnfilteredAggregationRule(ASTRule):
    """Detects aggregation without a WHERE clause."""

    id = "PERF-AGG-001"
    name = "Unfiltered Aggregation"
    description = "Detects COUNT(*), SUM(), AVG() without a WHERE clause on SELECT."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_AGGREGATION

    impact = "Aggregates entire table, expensive on large datasets"
    fix_guidance = "Add WHERE clause to filter rows before aggregation"

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if not query.is_select:
            return []

        has_agg = bool(
            list(ast.find_all(exp.Count))
            or list(ast.find_all(exp.Sum))
            or list(ast.find_all(exp.Avg))
        )

        if has_agg and not ast.find(exp.Where):
            return [
                self.create_issue(
                    query=query,
                    message="Aggregation without WHERE clause scans entire table.",
                    snippet=query.raw[:80],
                )
            ]
        return []


class OrderByInSubqueryRule(PatternRule):
    """Detects ORDER BY inside a subquery or CTE."""

    id = "PERF-AGG-002"
    name = "ORDER BY in Subquery"
    description = "Detects ORDER BY inside a subquery or CTE where it is typically meaningless."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_AGGREGATION

    pattern = r"(?i)\(\s*SELECT\b[^)]+\bORDER\s+BY\b"
    message_template = "ORDER BY in subquery is typically meaningless: {match}"

    impact = "ORDER BY in subquery is meaningless and wastes sort cost"
    fix_guidance = "Remove ORDER BY from subquery unless paired with LIMIT/TOP"


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



# =============================================================================
# 🛡️ RELIABILITY RULES
# =============================================================================


class UnsafeWriteRule(ASTRule):
    """Detects Critical Data Loss Risks (No WHERE)."""

    id = "REL-DATA-001"
    name = "Catastrophic Data Loss Risk"
    description = "Detects DELETE or UPDATE without WHERE clause."
    severity = Severity.CRITICAL
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if query.query_type not in ("DELETE", "UPDATE"):
            return []

        if not ast.find(exp.Where):
            return [
                self.create_issue(
                    query=query,
                    message=f"CRITICAL: {query.query_type} statement has no WHERE clause.",
                    snippet=query.raw,
                    severity=Severity.CRITICAL,
                    fix=Fix(
                        description="Add WHERE clause placeholder",
                        replacement=f"{query.raw.rstrip(';')} WHERE id = ...;",
                        is_safe=False,
                    ),
                    impact="Instant data loss of entire table content.",
                )
            ]
        return []


class DropTableRule(ASTRule):
    """Detects DROP TABLE statements."""

    id = "REL-DATA-004"
    name = "Destructive Schema Change (DROP)"
    description = "Detects DROP TABLE statements in code."
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if isinstance(ast, exp.Drop):
            return [
                self.create_issue(
                    query=query,
                    message="DROP statement detected.",
                    snippet=query.raw,
                    impact="Irreversible schema and data destruction. Ensure this is a migration "
                    "script.",
                )
            ]
        return []


class TruncateWithoutTransactionRule(PatternRule):
    """Detects TRUNCATE TABLE statements outside of an explicit transaction context."""

    id = "REL-DATA-002"
    name = "Truncate Without Transaction"
    description = (
        "Detects TRUNCATE TABLE statements outside of an explicit transaction context. "
        "TRUNCATE is non-transactional in many databases (MySQL, older PostgreSQL) and "
        "cannot be rolled back. Even in databases where it is transactional, it is "
        "rarely wrapped in a transaction in application code."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY

    pattern = (
        r"\bTRUNCATE\s+TABLE\b"
        r"|\bTRUNCATE\b(?!\s*--)"
    )
    message_template = "TRUNCATE TABLE detected outside explicit transaction: {match}"

    impact = (
        "TRUNCATE removes all rows instantly with no row-by-row logging, making "
        "recovery impossible without a backup in non-transactional databases."
    )
    fix_guidance = (
        "Wrap TRUNCATE in an explicit BEGIN/START TRANSACTION block with a subsequent "
        "COMMIT only after verification. Prefer DELETE with WHERE for recoverable "
        "operations. Use TRUNCATE only in controlled migration scripts."
    )


class AlterTableDestructiveRule(PatternRule):
    """Detects destructive ALTER TABLE operations."""

    id = "REL-DATA-003"
    name = "ALTER TABLE Without Backup Signal"
    description = (
        "Detects destructive ALTER TABLE operations: DROP COLUMN, MODIFY COLUMN "
        "(type change), and RENAME COLUMN. These operations can cause irreversible "
        "data loss or application breakage if not coordinated with application "
        "deployments."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY

    pattern = (
        r"\bALTER\s+TABLE\b.+\bDROP\s+COLUMN\b"
        r"|\bALTER\s+TABLE\b.+\bMODIFY\s+COLUMN\b"
        r"|\bALTER\s+TABLE\b.+\bRENAME\s+COLUMN\b"
        r"|\bALTER\s+TABLE\b.+\bCHANGE\s+COLUMN\b"
    )
    message_template = "Destructive ALTER TABLE operation detected: {match}"

    impact = (
        "DROP COLUMN permanently destroys column data. MODIFY COLUMN can silently "
        "truncate data if the new type is narrower. RENAME COLUMN breaks all "
        "application queries referencing the old name."
    )
    fix_guidance = (
        "Always take a full backup before destructive ALTER operations. Use "
        "expand-contract pattern for zero-downtime schema changes: add new column, "
        "migrate data, update application, then drop old column. Test in staging first."
    )


class MissingRollbackRule(PatternRule):
    """Detects BEGIN/START TRANSACTION blocks for rollback review."""

    id = "REL-TXN-001"
    name = "Missing Transaction Rollback Handler"
    description = (
        "Detects BEGIN/START TRANSACTION blocks that have a COMMIT but no ROLLBACK, "
        "indicating missing error handling. Transactions without ROLLBACK leave the "
        "database in an inconsistent state if an error occurs mid-transaction."
    )
    severity = Severity.INFO
    dimension = Dimension.RELIABILITY
    category = Category.REL_TRANSACTION

    pattern = r"\b(BEGIN|START\s+TRANSACTION)\b"
    message_template = "Transaction opened — verify ROLLBACK handler exists: {match}"

    impact = (
        "Without ROLLBACK, a failed transaction may partially commit changes, leaving "
        "data in an inconsistent state. This is especially dangerous for multi-step "
        "operations like financial transfers."
    )
    fix_guidance = (
        "Always pair BEGIN/COMMIT with a ROLLBACK in error handling. Use savepoints "
        "for partial rollbacks in complex transactions. In application code, use "
        "try/catch/finally patterns to ensure ROLLBACK on exception."
    )


class AutocommitDisabledRule(PatternRule):
    """Detects explicit disabling of autocommit mode."""

    id = "REL-TXN-002"
    name = "Autocommit Disable Detection"
    description = (
        "Detects explicit disabling of autocommit mode (SET autocommit = 0, "
        "SET IMPLICIT_TRANSACTIONS ON). When autocommit is disabled globally, every "
        "statement starts an implicit transaction that must be manually committed or "
        "rolled back, which can cause long-running locks and accidental data loss on "
        "connection drop."
    )
    severity = Severity.LOW
    dimension = Dimension.RELIABILITY
    category = Category.REL_TRANSACTION

    pattern = (
        r"\bSET\s+autocommit\s*=\s*0\b"
        r"|\bSET\s+IMPLICIT_TRANSACTIONS\s+ON\b"
    )
    message_template = "Autocommit disabled — risk of silent rollback on connection drop: {match}"

    impact = (
        "Disabling autocommit causes uncommitted changes to be silently rolled back "
        "on connection drop or application crash, leading to data loss. Long-running "
        "implicit transactions hold locks and degrade concurrency."
    )
    fix_guidance = (
        "Use explicit BEGIN/COMMIT blocks instead of disabling autocommit globally. "
        "If autocommit must be disabled, ensure every code path has explicit COMMIT "
        "or ROLLBACK. Monitor for long-running transactions via pg_stat_activity or "
        "information_schema.innodb_trx."
    )


class ExceptionSwallowedRule(PatternRule):
    """Detects exception handling blocks that swallow errors silently."""

    id = "REL-ERR-001"
    name = "Swallowed Exception Pattern"
    description = (
        "Detects exception handling blocks that swallow errors silently: WHEN OTHERS "
        "THEN NULL (Oracle), EXCEPTION WHEN OTHERS THEN (PL/pgSQL with no RAISE), "
        "and empty CATCH blocks in T-SQL. Swallowed exceptions hide data integrity "
        "failures and make debugging impossible."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_ERROR_HANDLING

    pattern = r"\bWHEN\s+OTHERS\s+THEN\s+NULL\b"
    message_template = "Exception handler may be swallowing errors silently: {match}"

    impact = (
        "Silent exception swallowing means failed operations appear to succeed. Data "
        "integrity violations, constraint failures, and deadlocks go undetected, "
        "leading to corrupted application state."
    )
    fix_guidance = (
        "Always re-raise or log exceptions. In Oracle PL/SQL use RAISE or "
        "RAISE_APPLICATION_ERROR. In PostgreSQL use RAISE EXCEPTION. In T-SQL use "
        "THROW or RAISERROR. Never use WHEN OTHERS THEN NULL in production code."
    )


class LongTransactionWithoutSavepointRule(PatternRule):
    """Detects SAVEPOINT usage for review in long transactions."""

    id = "REL-REC-001"
    name = "Missing Savepoint in Long Transaction"
    description = (
        "Detects long multi-statement transactions (containing 3 or more DML "
        "operations: INSERT, UPDATE, DELETE) without a SAVEPOINT. Long transactions "
        "without savepoints cannot be partially rolled back, forcing a full rollback "
        "on any error."
    )
    severity = Severity.INFO
    dimension = Dimension.RELIABILITY
    category = Category.REL_RECOVERY

    pattern = r"\bSAVEPOINT\b"
    message_template = "Long transaction detected — consider using SAVEPOINTs for partial recovery: {match}"

    impact = (
        "A failure in step 10 of a 10-step transaction forces rollback of all "
        "previous steps. Savepoints allow partial recovery and reduce re-work cost."
    )
    fix_guidance = (
        "Use SAVEPOINT after logically complete sub-operations within long "
        "transactions. Use ROLLBACK TO SAVEPOINT to recover from partial failures "
        "without abandoning the entire transaction."
    )


# =============================================================================
# 📋 COMPLIANCE RULES
# =============================================================================


class PIIExposureRule(PatternRule):
    """Detects potential PII selection."""

    id = "COMP-GDPR-001"
    name = "Potential PII Selection"
    description = "Detects selection of common PII column names (email, ssn, password)."
    severity = Severity.MEDIUM
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_GDPR

    pattern = r"(?i)\b(email|ssn|social_security|credit_card|cc_num|passport)\b"
    message_template = "Potential PII column accessed: {match}"
    impact = "Accessing PII requires audit logging and strict access controls under GDPR/CCPA."


class UnencryptedSensitiveColumnRule(PatternRule):
    """Detects sensitive column names created without encryption hints."""

    id = "COMP-SEC-001"
    name = "Unencrypted Sensitive Column Definition"
    description = (
        "Detects CREATE TABLE statements defining columns with sensitive names "
        "(password, secret, token, ssn, credit_card, cvv, pin) using plain text "
        "types (VARCHAR, TEXT, CHAR) without encryption hints in the column name "
        "or comment."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_PCI

    pattern = (
        r"\bCREATE\s+TABLE\b.+\b(password|secret|token|ssn|credit_card|cvv|pin)\b"
        r".+\b(VARCHAR|TEXT|CHAR)\b"
    )
    message_template = "Sensitive column defined with plain text type — consider encryption: {match}"

    impact = (
        "Storing sensitive values in plain text columns violates PCI-DSS, HIPAA, "
        "and GDPR requirements and exposes data if the database is compromised."
    )
    fix_guidance = (
        "Use application-level encryption before storing, or database-level "
        "transparent encryption. Consider column names like password_hash or "
        "token_encrypted to signal encrypted storage."
    )


class RetentionPolicyMissingRule(PatternRule):
    """Detects CREATE TABLE on tables with time-series or audit naming without TTL hints."""

    id = "COMP-RET-001"
    name = "Missing Retention Policy Signal"
    description = (
        "Detects CREATE TABLE statements for tables with audit, log, history, or "
        "event naming patterns. Such tables typically require a data retention "
        "policy under GDPR Article 5(1)(e) and similar regulations but rarely "
        "have one enforced at the schema level."
    )
    severity = Severity.LOW
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_GDPR

    pattern = (
        r"\bCREATE\s+TABLE\b.+\b(audit|audits|audit_log|event_log|history|"
        r"logs|access_log|activity_log)\b"
    )
    message_template = "Table with audit/log naming detected — verify retention policy exists: {match}"

    impact = (
        "Indefinite retention of audit and log data violates GDPR storage "
        "limitation principles and increases breach exposure surface."
    )
    fix_guidance = (
        "Implement a documented retention policy. Use partitioning with scheduled "
        "partition drops, or a scheduled DELETE WHERE created_at < NOW() - INTERVAL. "
        "Document the retention period in a data inventory."
    )


class CrossBorderDataTransferRule(PatternRule):
    """Detects DBLINK or foreign server queries that may indicate cross-border data transfer."""

    id = "COMP-GDPR-002"
    name = "Potential Cross-Border Data Transfer"
    description = (
        "Detects use of DBLINK, foreign data wrappers (postgres_fdw, dblink), "
        "or OPENROWSET which may transfer personal data across database boundaries "
        "or geographic regions without adequate GDPR safeguards."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_GDPR

    pattern = (
        r"\bDBLINK\s*\("
        r"|\bOPENROWSET\s*\("
        r"|\bCREATE\s+SERVER\b"
        r"|\bCREATE\s+FOREIGN\s+TABLE\b"
    )
    message_template = "Cross-database or foreign data access detected — verify GDPR transfer compliance: {match}"

    impact = (
        "Transferring personal data to foreign servers in non-adequate countries "
        "without SCCs or BCRs violates GDPR Chapter V and can result in significant fines."
    )
    fix_guidance = (
        "Document all cross-border data flows in your data inventory. Ensure "
        "Standard Contractual Clauses or Binding Corporate Rules are in place. "
        "Prefer data minimization — transfer only pseudonymized or anonymized data."
    )


class RightToErasureRule(PatternRule):
    """Detects DELETE on tables with PII-related names, flagging for erasure compliance review."""

    id = "COMP-GDPR-003"
    name = "Right to Erasure — Verify Cascade Completeness"
    description = (
        "Detects DELETE statements on tables with user, customer, account, profile, "
        "or member naming. GDPR Article 17 requires complete erasure across all "
        "related tables. A single-table DELETE may leave PII in audit logs, "
        "backups, or related tables."
    )
    severity = Severity.INFO
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_GDPR

    pattern = (
        r"\bDELETE\s+FROM\s+(users|customers|accounts|profiles|members|"
        r"user_data|customer_data|personal_data)\b"
    )
    message_template = "DELETE on PII table detected — verify GDPR erasure completeness: {match}"

    impact = (
        "Incomplete erasure leaves PII in related tables, audit logs, caches, "
        "and backups, violating GDPR Article 17 and exposing the organization "
        "to regulatory penalties."
    )
    fix_guidance = (
        "Implement cascading deletes or a dedicated erasure procedure that covers "
        "all related tables. Document which systems hold personal data and verify "
        "backup purge schedules. Consider pseudonymization as an alternative to deletion."
    )


class AuditLogTamperingRule(PatternRule):
    """Detects DELETE or UPDATE on audit/log tables."""

    id = "COMP-AUD-001"
    name = "Audit Log Tampering Risk"
    description = (
        "Detects DELETE or UPDATE statements targeting audit, log, or event tables. "
        "Modifying audit logs undermines non-repudiation requirements under SOX, "
        "PCI-DSS 10.5, and HIPAA audit controls."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_SOX

    pattern = (
        r"\b(DELETE\s+FROM|UPDATE)\s+\w*(audit|audit_log|event_log|access_log|"
        r"activity_log|audit_trail|system_log)\w*\b"
    )
    message_template = "Modification of audit/log table detected — potential compliance violation: {match}"

    impact = (
        "Modifying audit logs violates regulatory non-repudiation requirements "
        "and may constitute evidence tampering. PCI-DSS 10.5 explicitly requires "
        "audit logs to be protected from modification."
    )
    fix_guidance = (
        "Audit tables should be append-only. Use INSERT-only permissions on log "
        "tables. Implement write-once storage for compliance archives. Use "
        "database roles to prevent UPDATE/DELETE on audit tables."
    )


class ConsentTableMissingRule(PatternRule):
    """Detects INSERT into marketing or communication tables without a consent table join signal."""

    id = "COMP-GDPR-004"
    name = "Marketing Insert Without Consent Signal"
    description = (
        "Detects INSERT INTO statements targeting marketing, newsletter, campaign, "
        "or mailing list tables. GDPR Article 7 requires documented consent before "
        "adding users to marketing lists. A bare INSERT with no consent reference "
        "is a compliance signal."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_GDPR

    pattern = (
        r"\bINSERT\s+INTO\s+\w*(marketing|newsletter|mailing_list|campaign|"
        r"subscribers|email_list)\w*\b"
    )
    message_template = "INSERT into marketing/communication table — verify GDPR consent was recorded: {match}"

    impact = (
        "Adding users to marketing lists without recorded consent violates GDPR "
        "Article 7 and ePrivacy Directive, exposing the organization to "
        "regulatory complaints and fines."
    )
    fix_guidance = (
        "Ensure consent is recorded in a consent management table before INSERT. "
        "Include consent_id or consent_timestamp as a required foreign key in "
        "marketing tables. Audit consent validity before each campaign."
    )


# =============================================================================
# 📝 QUALITY RULES
# =============================================================================


class ImplicitJoinRule(ASTRule):
    """Detects implicit joins (comma-separated tables)."""

    id = "QUAL-MODERN-001"
    name = "Implicit Join Syntax"
    description = "Detects old-style implicit joins using commas in FROM clause."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        if not query.is_select:
            return []

        # Check if FROM has multiple tables in the same From node (comma separation)
        from_clause = ast.find(exp.From)
        if from_clause and len(from_clause.expressions) > 1:
            return [
                self.create_issue(
                    query=query,
                    message="Implicit join syntax detected (comma-separated tables).",
                    snippet=str(from_clause),
                    fix=Fix(
                        description="Convert to explicit INNER JOIN",
                        replacement="... FROM table1 JOIN table2 ON ...",
                        is_safe=False,
                    ),
                    impact="Implicit joins are harder to read and prone to accidental cross-joins.",
                )
            ]
        return []


class NullComparisonRule(PatternRule):
    """Detects incorrect NULL comparisons using = or != instead of IS NULL / IS NOT NULL."""

    id = "QUAL-NULL-001"
    name = "Incorrect NULL Comparison"
    description = (
        "Detects comparisons using = NULL or != NULL (and <> NULL) instead of "
        "IS NULL or IS NOT NULL. In SQL, NULL = NULL evaluates to NULL (unknown), "
        "not TRUE, so these comparisons always return no rows."
    )
    severity = Severity.HIGH
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY

    pattern = (
        r"(?<![A-Z_])\s*=\s*NULL\b"
        r"|\bNULL\s*=\s*(?![A-Z_])"
        r"|!=\s*NULL\b"
        r"|<>\s*NULL\b"
    )
    message_template = "Incorrect NULL comparison detected — use IS NULL or IS NOT NULL: {match}"

    impact = (
        "Using = NULL or != NULL silently returns zero rows regardless of actual "
        "NULL values, causing data to appear missing and logic to fail without errors."
    )
    fix_guidance = (
        "Replace '= NULL' with 'IS NULL' and '!= NULL' or '<> NULL' with "
        "'IS NOT NULL'. Use COALESCE() if a default value is needed instead of NULL handling."
    )


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

    pattern = r"(?i)^\s*SELECT\s+.+(?<!\bFROM\b.+)$"
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


class HardcodedDateRule(PatternRule):
    """Detects hardcoded date literals in WHERE clauses."""

    id = "QUAL-MODERN-002"
    name = "Hardcoded Date Literal in Filter"
    description = (
        "Detects hardcoded date strings in WHERE clauses (e.g., WHERE date = '2023-01-01'). "
        "Hardcoded dates create maintenance burden, break time-based logic silently "
        "as time passes, and are a common source of stale query bugs."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN

    pattern = (
        r"\bWHERE\b.+['\"](\d{4}-\d{2}-\d{2})['\"]"
    )
    message_template = "Hardcoded date literal detected in WHERE clause — consider using parameters: {match}"

    impact = (
        "Hardcoded dates become stale and cause queries to return unexpected "
        "results or no results as time passes. They also prevent query plan reuse."
    )
    fix_guidance = (
        "Replace hardcoded dates with parameterized values (?), bind variables "
        "(:date), or dynamic expressions like NOW(), CURRENT_DATE, or "
        "CURRENT_DATE - INTERVAL '30 days'."
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


class DuplicateConditionRule(PatternRule):
    """Detects obvious duplicate WHERE conditions."""

    id = "QUAL-DRY-001"
    name = "Duplicate WHERE Condition"
    description = (
        "Detects WHERE clauses containing the same column compared to the same "
        "value twice with AND (e.g., WHERE status = 'active' AND status = 'active'). "
        "Duplicate conditions add noise, confuse readers, and may indicate a "
        "copy-paste error hiding a logic bug."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.QUALITY
    category = Category.QUAL_DRY

    pattern = (
        r"\bWHERE\b.+\b(\w+)\s*=\s*('[^']*'|\d+)\s+AND\s+\1\s*=\s*\2"
    )
    message_template = "Duplicate WHERE condition detected — possible copy-paste error: {match}"

    impact = (
        "Duplicate conditions waste parser cycles and obscure intent. They often "
        "indicate a copy-paste error where the second condition should have been "
        "different (e.g., OR instead of AND, or a different value)."
    )
    fix_guidance = (
        "Remove the duplicate condition. If both conditions were intended to "
        "filter on different values, verify the logic — AND with two equal "
        "conditions on the same column always reduces to a single condition."
    )


class UnionWithoutAllRule(PatternRule):
    """Detects UNION without ALL where UNION ALL is likely intended for performance."""

    id = "QUAL-MODERN-003"
    name = "UNION Without ALL — Implicit Deduplication"
    description = (
        "Detects UNION without ALL. UNION performs an implicit DISTINCT which "
        "requires a sort or hash operation over the full result set. If duplicate "
        "elimination is not required, UNION ALL is significantly faster."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_MODERN

    pattern = r"\bUNION\b(?!\s+ALL\b)"
    message_template = "UNION without ALL detected — use UNION ALL if duplicates are not a concern: {match}"

    impact = (
        "UNION deduplicates results using an expensive sort or hash operation. "
        "On large result sets this adds significant overhead compared to UNION ALL."
    )
    fix_guidance = (
        "If the result sets cannot contain meaningful duplicates, replace UNION "
        "with UNION ALL. If deduplication is required, keep UNION and add a "
        "comment explaining why to prevent future 'optimization' regressions."
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


# =============================================================================
# 🔒 SECURITY RULES (Extended)
# =============================================================================


class DynamicSQLExecutionRule(PatternRule):
    """Detects dynamic SQL construction and execution."""

    id = "SEC-INJ-002"
    name = "Dynamic SQL Execution"
    description = (
        "Detects dynamic SQL construction and execution via EXEC(), EXECUTE(), "
        "EXECUTE IMMEDIATE, sp_executesql, and PREPARE FROM variable/concatenation. "
        "Dynamic SQL built from string concatenation or variables is the primary "
        "mechanism for SQL injection in stored procedures."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = (
        r"EXEC\s*\("
        r"|EXECUTE\s*\("
        r"|EXECUTE\s+IMMEDIATE\b"
        r"|\bsp_executesql\b"
        r"|\bPREPARE\s+\w+\s+FROM\s+@"
        r"|\bPREPARE\s+\w+\s+FROM\s+CONCAT\s*\("
    )
    message_template = "Dynamic SQL execution detected: {match}"

    impact = (
        "Attackers can inject arbitrary SQL through unsanitized inputs passed into "
        "dynamically constructed queries, leading to data theft, privilege escalation, "
        "or complete database compromise."
    )
    fix_guidance = (
        "Use parameterized queries or stored procedures with typed parameters. "
        "Replace string concatenation with sp_executesql parameter binding. "
        "For MySQL, use PREPARE with placeholder syntax (?) instead of variable interpolation."
    )


class TautologicalOrConditionRule(PatternRule):
    """Detects always-true OR conditions."""

    id = "SEC-INJ-003"
    name = "Tautological OR Condition"
    description = (
        "Detects always-true OR conditions such as OR 1=1, OR 'a'='a', and OR TRUE. "
        "These are classic SQL injection payload indicators and should be investigated "
        "when found in application queries."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = (
        r"\bOR\s+1\s*=\s*1\b"
        r"|\bOR\s+'[^']*'\s*=\s*'[^']*'"
        r"|\bOR\s+\"[^\"]*\"\s*=\s*\"[^\"]*\""
        r"|\bOR\s+TRUE\b"
    )
    message_template = "Tautological OR condition detected: {match}"

    impact = (
        "Tautological OR conditions bypass authentication and authorization checks, "
        "allowing attackers to retrieve all rows, bypass login forms, or escalate privileges."
    )
    fix_guidance = (
        "Use parameterized queries to prevent injection. If the tautological condition "
        "is intentional (e.g., for testing), remove it before deploying to production. "
        "Investigate the source of the query for injection vulnerabilities."
    )


class TimeBasedBlindInjectionRule(PatternRule):
    """Detects time delay functions used in blind SQL injection."""

    id = "SEC-INJ-004"
    name = "Time-Based Blind Injection Indicator"
    description = (
        "Detects time delay functions commonly used in blind SQL injection attacks: "
        "WAITFOR DELAY, SLEEP(), pg_sleep(), and BENCHMARK(). These functions have "
        "almost zero legitimate use in application SQL queries and are strong indicators "
        "of injection attempts or testing."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = (
        r"\bWAITFOR\s+DELAY\b"
        r"|\bSLEEP\s*\("
        r"|\bpg_sleep\s*\("
        r"|\bBENCHMARK\s*\("
    )
    message_template = "Time-based blind injection indicator detected: {match}"

    impact = (
        "Blind SQL injection allows attackers to extract data one bit at a time by "
        "measuring response delays. Even without visible output, attackers can fully "
        "compromise a database through time-based techniques."
    )
    fix_guidance = (
        "Remove time delay functions from application queries. Use parameterized "
        "queries to prevent injection. If used for testing or scheduling, move the "
        "logic to application code outside of SQL."
    )


class GrantToPublicRule(PatternRule):
    """Detects GRANT statements to the PUBLIC role."""

    id = "SEC-AUTH-002"
    name = "Grant to PUBLIC Role"
    description = (
        "Detects GRANT statements that assign permissions to the PUBLIC role. PUBLIC "
        "includes every user in the database, making this a violation of the "
        "least-privilege principle."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r"\bGRANT\b.+\bTO\s+PUBLIC\b"
    message_template = "Grant to PUBLIC role detected: {match}"

    impact = (
        "Granting permissions to PUBLIC gives every current and future database user "
        "access to the specified objects, creating an uncontrollable access surface "
        "and potential data exposure."
    )
    fix_guidance = (
        "Grant permissions to specific roles or users instead of PUBLIC. Create "
        "application-specific roles with minimal required permissions and assign "
        "users to those roles."
    )


class UserCreationWithoutPasswordRule(PatternRule):
    """Detects CREATE USER/LOGIN without a password clause."""

    id = "SEC-AUTH-003"
    name = "User Creation Without Password"
    description = (
        "Detects CREATE USER and CREATE LOGIN statements that do not include a "
        "password clause (IDENTIFIED BY, WITH PASSWORD, PASSWORD =). Creating "
        "database users without passwords creates unauthenticated access points."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r"\bCREATE\s+(USER|LOGIN)\b(?![\s\S]*(IDENTIFIED\s+BY|WITH\s+PASSWORD|PASSWORD\s*=))"
    message_template = "User/login created without password: {match}"

    impact = (
        "Passwordless database accounts can be accessed by anyone who knows the "
        "username, enabling unauthorized data access, modification, or administrative "
        "actions."
    )
    fix_guidance = (
        "Always specify a strong password when creating users or logins. Use "
        "IDENTIFIED BY (Oracle/MySQL), WITH PASSWORD (SQL Server), or PASSWORD "
        "(PostgreSQL). Enforce password complexity policies."
    )


class PasswordPolicyBypassRule(PatternRule):
    """Detects disabling of password policy enforcement."""

    id = "SEC-AUTH-004"
    name = "Password Policy Bypass"
    description = (
        "Detects disabling of password policy enforcement (CHECK_POLICY = OFF) or "
        "password expiration checks (CHECK_EXPIRATION = OFF) in SQL Server login "
        "management. Disabling these allows weak and non-expiring passwords."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = (
        r"\bCHECK_POLICY\s*=\s*OFF\b"
        r"|\bCHECK_EXPIRATION\s*=\s*OFF\b"
    )
    message_template = "Password policy bypass detected: {match}"

    impact = (
        "Weak passwords without policy enforcement are vulnerable to brute force and "
        "credential stuffing attacks. Non-expiring passwords increase the window for "
        "compromised credentials to be exploited."
    )
    fix_guidance = (
        "Always keep CHECK_POLICY = ON and CHECK_EXPIRATION = ON. Use strong password "
        "complexity requirements. Implement password rotation policies through "
        "database-level enforcement."
    )


class DataExfiltrationViaFileRule(PatternRule):
    """Detects SQL file operations that can export or read data."""

    id = "SEC-DATA-001"
    name = "Data Exfiltration via File Operations"
    description = (
        "Detects SQL file operations that can export data to the filesystem or read "
        "arbitrary files: INTO OUTFILE, INTO DUMPFILE, LOAD_FILE(), LOAD DATA INFILE, "
        "BULK INSERT, and COPY FROM/TO PROGRAM. These are primary vectors for data "
        "exfiltration and arbitrary file read."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE

    pattern = (
        r"\bINTO\s+OUTFILE\b"
        r"|\bINTO\s+DUMPFILE\b"
        r"|\bLOAD_FILE\s*\("
        r"|\bLOAD\s+DATA\s+INFILE\b"
        r"|\bBULK\s+INSERT\b"
        r"|\bCOPY\b.+\bFROM\s+PROGRAM\b"
        r"|\bCOPY\b.+\bTO\s+PROGRAM\b"
    )
    message_template = "Data exfiltration via file operation detected: {match}"

    impact = (
        "Attackers can export entire tables to attacker-readable locations, read "
        "sensitive OS files (e.g., /etc/passwd, configuration files), or execute "
        "arbitrary OS commands via COPY PROGRAM."
    )
    fix_guidance = (
        "Restrict FILE privilege in MySQL. Disable LOAD DATA INFILE via "
        "local_infile=0. Revoke COPY permissions in PostgreSQL. Use application-level "
        "export mechanisms with proper access controls instead of SQL-level file operations."
    )


class RemoteDataAccessRule(PatternRule):
    """Detects remote/linked data access functions."""

    id = "SEC-DATA-002"
    name = "Remote/Linked Data Access"
    description = (
        "Detects remote data access functions that can connect to external servers: "
        "OPENROWSET, OPENDATASOURCE, OPENQUERY (SQL Server), and dblink functions "
        "(PostgreSQL). These can be exploited for data exfiltration and lateral "
        "movement to other database servers."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE

    pattern = (
        r"\bOPENROWSET\s*\("
        r"|\bOPENDATASOURCE\s*\("
        r"|\bOPENQUERY\s*\("
        r"|\bdblink_connect\s*\("
        r"|\bdblink_exec\s*\("
        r"|\bdblink\s*\("
    )
    message_template = "Remote data access detected: {match}"

    impact = (
        "Attackers can use remote access functions to exfiltrate data to external "
        "servers, pivot to other databases in the network, or connect to "
        "attacker-controlled servers to stage further attacks."
    )
    fix_guidance = (
        "Disable Ad Hoc Distributed Queries in SQL Server. Remove linked server "
        "connections that are not required. Restrict dblink extension usage in "
        "PostgreSQL. Use application-level integration instead of database-to-database "
        "direct connections."
    )


class DangerousServerConfigRule(PatternRule):
    """Detects sp_configure enabling dangerous SQL Server features."""

    id = "SEC-CFG-001"
    name = "Dangerous Server Configuration"
    description = (
        "Detects sp_configure commands that enable dangerous SQL Server features: "
        "xp_cmdshell (OS command execution), Ole Automation Procedures (COM object "
        "access), CLR integration (arbitrary .NET code execution), and Ad Hoc "
        "Distributed Queries (remote data access)."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_ACCESS

    pattern = (
        r"\bsp_configure\b.+\bxp_cmdshell\b"
        r"|\bsp_configure\b.+\bOle\s+Automation\b"
        r"|\bsp_configure\b.+\bclr\s+enabled\b"
        r"|\bsp_configure\b.+\bAd\s+Hoc\s+Distributed\s+Queries\b"
    )
    message_template = "Dangerous server configuration detected: {match}"

    impact = (
        "Enabling xp_cmdshell gives SQL users full operating system command execution. "
        "Ole Automation and CLR allow arbitrary code execution within the database "
        "process. These are the most common post-exploitation steps in SQL Server attacks."
    )
    fix_guidance = (
        "Keep dangerous features disabled. Use sp_configure to verify settings. If "
        "xp_cmdshell or CLR is required, restrict access to specific logins and audit "
        "all usage. Never enable these features in production without a documented "
        "security review."
    )


class OverprivilegedExecutionContextRule(PatternRule):
    """Detects stored procedures with elevated execution contexts."""

    id = "SEC-PRIV-001"
    name = "Overprivileged Execution Context"
    description = (
        "Detects stored procedures, functions, or grants that use elevated execution "
        "contexts: EXECUTE AS dbo/sa/sysadmin, EXECUTE AS OWNER/SELF, SECURITY "
        "DEFINER (MySQL/PostgreSQL), WITH ADMIN OPTION, and WITH GRANT OPTION. "
        "These create privilege escalation paths."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = (
        r"\bEXECUTE\s+AS\s+(USER\s*=\s*)?'(dbo|sa|sysadmin)'"
        r"|\bEXECUTE\s+AS\s+LOGIN\s*=\s*'(sa|sysadmin)'"
        r"|\bEXECUTE\s+AS\s+(OWNER|SELF)\b"
        r"|\bSECURITY\s+DEFINER\b"
        r"|\bWITH\s+ADMIN\s+OPTION\b"
        r"|\bWITH\s+GRANT\s+OPTION\b"
    )
    message_template = "Overprivileged execution context detected: {match}"

    impact = (
        "Stored procedures running as high-privilege accounts can be exploited for "
        "privilege escalation. WITH ADMIN/GRANT OPTION creates uncontrolled permission "
        "propagation where any granted user can re-grant to others."
    )
    fix_guidance = (
        "Use EXECUTE AS CALLER or SECURITY INVOKER instead of DEFINER/OWNER. Avoid "
        "WITH ADMIN OPTION and WITH GRANT OPTION unless absolutely necessary. Run "
        "stored procedures with the minimum privileges required. Audit all objects "
        "running as dbo or sa."
    )


# =============================================================================
# COST RULES
# =============================================================================


class FullTableScanRule(PatternRule):
    """Detects queries that likely trigger full table scans by lacking WHERE clauses."""

    id = "COST-COMPUTE-001"
    name = "Full Table Scan on Large Tables"
    description = (
        "Detects queries that likely trigger full table scans by lacking WHERE clauses "
        "on SELECT statements. Full scans consume excessive compute and I/O credits in "
        "cloud databases."
    )
    severity = Severity.HIGH
    dimension = Dimension.COST
    category = Category.COST_COMPUTE

    pattern = r"\bSELECT\b(?!\s+\*\s+INTO\b).*?\bFROM\b(?:(?!\bWHERE\b).)*?(?:;|$)"
    message_template = "Potential full table scan missing WHERE clause: {match}"

    impact = (
        "Full table scans linearly increase compute cost with table size. On cloud "
        "databases (AWS RDS, Azure SQL, GCP CloudSQL), this wastes IOPS and CPU credits, "
        "especially on large tables."
    )
    fix_guidance = (
        "Add a WHERE clause to filter rows. If a full scan is truly needed, consider "
        "using a separate analytics replica or data warehouse (e.g., BigQuery, "
        "Redshift) to avoid impacting OLTP workloads and costs."
    )


class ExpensiveWindowFunctionRule(ASTRule):
    """Detects window functions used without PARTITION BY."""

    id = "COST-COMPUTE-002"
    name = "Expensive Window Functions Without Partitioning"
    description = (
        "Detects window functions (ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD, etc.) used "
        "without PARTITION BY. Without partitioning, the entire dataset is processed "
        "as one partition, increasing memory and compute costs."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_COMPUTE

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Window):
                args = getattr(node, "args", {})
                partition = args.get('partition_by')
                if not partition or (isinstance(partition, list) and len(partition) == 0):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="Expensive window function without PARTITION BY detected.",
                            snippet=str(node)[:100],
                            impact=(
                                "Window functions without partitioning process the entire result set in a single "
                                "partition, consuming high memory and CPU. In serverless databases (Aurora Serverless, "
                                "Synapse), this can trigger aggressive scaling and cost spikes."
                            ),
                            fix=Fix(
                                description="Add PARTITION BY clause",
                                replacement="",
                                is_safe=False,
                            ),
                        )
                    )
        return issues


class SelectStarInETLRule(ASTRule):
    """Detects SELECT * in CREATE TABLE AS SELECT (CTAS) or INSERT INTO ... SELECT."""

    id = "COST-STORAGE-001"
    name = "SELECT * in ETL/CTAS Queries"
    description = (
        "Detects SELECT * in CREATE TABLE AS SELECT (CTAS), INSERT INTO ... SELECT, "
        "or other data persistence patterns. This copies unnecessary columns into "
        "storage, inflating storage and backup costs."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_STORAGE

    def _has_select_star(self, select_node: Any) -> bool:
        if hasattr(select_node, "expressions"):
            for expr in select_node.expressions:
                if isinstance(expr, exp.Star):
                    return True
        return False

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            is_ctas = isinstance(node, exp.Create) and getattr(node, "kind", "") == 'TABLE'
            is_insert = isinstance(node, exp.Insert)
            
            if is_ctas or is_insert:
                select = getattr(node, "expression", None)
                if select and isinstance(select, exp.Select):
                    if self._has_select_star(select):
                        issues.append(
                            self.create_issue(
                                query=query,
                                message="SELECT * in persistence query detected.",
                                snippet=str(node)[:100],
                                impact=(
                                    "Storing unnecessary columns increases storage costs linearly with row count. "
                                    "In columnar stores (Redshift, Snowflake), this also increases metadata "
                                    "overhead and backup costs."
                                ),
                                fix=Fix(
                                    description="Explicitly list columns",
                                    replacement="",
                                    is_safe=False,
                                ),
                            )
                        )
        return issues


class RedundantOrderByRule(ASTRule):
    """Detects ORDER BY clauses inside subqueries where the outer query doesn't use LIMIT."""

    id = "COST-IO-001"
    name = "Redundant ORDER BY in Subqueries"
    description = (
        "Detects ORDER BY clauses inside subqueries where the outer query re-sorts "
        "or doesn't use ordering. Sorting is expensive (disk I/O for temp tables) "
        "and wasteful if results are re-sorted."
    )
    severity = Severity.LOW
    dimension = Dimension.COST
    category = Category.COST_IO

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Subquery):
                inner_select = getattr(node, "this", None)
                if isinstance(inner_select, exp.Select):
                    args = getattr(inner_select, "args", {})
                    if args.get('order'):
                        has_limit = args.get('limit') is not None
                        if not has_limit:
                            issues.append(
                                self.create_issue(
                                    query=query,
                                    message="Redundant ORDER BY in subquery detected.",
                                    snippet=str(inner_select)[:100],
                                    impact=(
                                        "Unnecessary sorting forces the database to write intermediate results to "
                                        "disk (tempdb). In cloud databases, this increases I/O costs and can exhaust "
                                        "allocated IOPS, throttling queries."
                                    ),
                                    fix=Fix(
                                        description="Remove ORDER BY from subquery",
                                        replacement="",
                                        is_safe=False,
                                    ),
                                )
                            )
        return issues


class CrossRegionDataTransferCostRule(PatternRule):
    """Flags queries using database links, federated queries, or external tables."""

    id = "COST-NETWORK-001"
    name = "Cross-Region Data Transfer"
    description = (
        "Flags queries using database links, federated queries, or external table "
        "references that may cause cross-region data transfer. Cloud providers "
        "charge heavily for egress traffic."
    )
    severity = Severity.INFO
    dimension = Dimension.COST
    category = Category.COST_NETWORK

    pattern = r"(?i)\b(OPENQUERY|OPENDATASOURCE|EXTERNAL\s+TABLE|DBLink|@[\w\.]+)\b"
    message_template = "Potential cross-region data transfer detected: {match}"

    impact = (
        "Cross-region queries incur data egress charges (e.g., $0.09/GB in AWS). A "
        "single unoptimized federated query can transfer terabytes and generate "
        "unexpected bills."
    )
    fix_guidance = (
        "Minimize cross-region queries. Use data replication (read replicas, CDC) or "
        "cache results locally. For analytics, stage data in the same region as compute "
        "resources."
    )


class SecondOrderSQLInjectionRule(ASTRule):
    """Detects INSERT/UPDATE statements storing user-controllable data that may later be concatenated into dynamic SQL."""

    id = "SEC-INJ-005"
    name = "Second-Order SQL Injection Risk"
    description = (
        "Detects INSERT/UPDATE statements storing user-controllable data (usernames, emails, comments, etc.) "
        "that may later be concatenated into dynamic SQL, enabling second-order injection."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        # Columns that commonly store user input later used unsafely
        dangerous_columns = {
            'username', 'user_name', 'email', 'name', 'first_name', 'last_name',
            'comment', 'comments', 'description', 'title', 'subject', 'message',
            'address', 'notes', 'bio', 'about', 'query', 'search', 'filter',
            'filename', 'filepath', 'url', 'callback', 'redirect'
        }
        
        for node in ast.walk():
            if isinstance(node, (exp.Insert, exp.Update)):
                # Get column names being set
                columns = self._extract_target_columns(node)
                
                dangerous_found = columns & dangerous_columns
                if dangerous_found:
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"Storing user-controllable data in columns that risk second-order injection: {', '.join(dangerous_found)}",
                            snippet=str(node)[:100],
                            impact=(
                                "Data stored today may be concatenated into SQL tomorrow. Second-order injection bypasses input "
                                "validation performed only at write time, and is often missed by WAFs and scanners."
                            ),
                            fix=Fix(
                                description="Parameterize all queries that retrieve and use stored data.",
                                replacement="",
                                is_safe=False,
                            ),
                        )
                    )
        
        return issues

    def _extract_target_columns(self, node: Any) -> set[str]:
        columns = set()
        # Handle INSERT column list
        if isinstance(node, exp.Insert):
            if node.this and hasattr(node.this, 'expressions'):
                for col in node.this.expressions:
                    if hasattr(col, 'name'):
                        columns.add(col.name.lower())
        # Handle UPDATE SET clauses
        elif isinstance(node, exp.Update):
            for expr in node.expressions:
                if isinstance(expr, exp.EQ) and hasattr(expr.this, 'name'):
                    columns.add(expr.this.name.lower())
        return columns


class LikeWildcardInjectionRule(ASTRule):
    """Detects LIKE clauses that may allow user-injected % or _ wildcards."""

    id = "SEC-INJ-006"
    name = "LIKE Clause Wildcard Injection"
    description = (
        "Detects LIKE clauses that may allow user-injected % or _ wildcards, which can transform "
        "indexed lookups into expensive full table scans (DoS vector)."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, exp.Like):
                pattern = getattr(node, "expression", None)  # The LIKE pattern
                
                # Check if pattern is a parameter placeholder or simple literal
                # Parameters suggest user input that should be escaped
                if isinstance(pattern, exp.Placeholder):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="LIKE clause with parameter placeholder - ensure wildcards are escaped",
                            snippet=str(node)[:100],
                            impact=(
                                "Unescaped wildcards in LIKE clauses let attackers inject % to force full table scans. "
                                "A single % prefix defeats all index optimizations, enabling performance-based DoS."
                            ),
                            fix=Fix(
                                description="Escape % and _ in user input before use in LIKE.",
                                replacement="",
                                is_safe=False,
                            ),
                        )
                    )
                # Check for double wildcards which are especially expensive
                elif isinstance(pattern, exp.Literal):
                    pattern_str = str(getattr(pattern, "this", ""))
                    if pattern_str.startswith('%') and pattern_str.endswith('%'):
                        issues.append(
                            self.create_issue(
                                query=query,
                                message="Double-sided wildcard in LIKE defeats index usage",
                                snippet=str(node)[:100],
                                impact=(
                                    "Unescaped wildcards in LIKE clauses let attackers inject % to force full table scans. "
                                    "A single % prefix defeats all index optimizations, enabling performance-based DoS."
                                ),
                                fix=Fix(
                                    description="Escape % and _ in user input before use in LIKE. Consider full-text search for complex patterns.",
                                    replacement="",
                                    is_safe=False,
                                ),
                            )
                        )
        
        return issues


class WeakHashingAlgorithmRule(PatternRule):
    """Detects use of cryptographically broken hashing algorithms (MD5, SHA1)."""

    id = "SEC-CRYPTO-001"
    name = "Weak Hashing Algorithm"
    description = (
        "Detects use of cryptographically broken hashing algorithms (MD5, SHA1) for password "
        "or sensitive data hashing."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_CRYPTO

    pattern = r"\b(MD5|SHA1|SHA)\s*\(\s*[^)]*\b(password|passwd|pwd|secret|token|key|credential)\b"
    message_template = "Weak hashing algorithm detected: {match}"
    
    impact = (
        "MD5 and SHA1 are cryptographically broken. GPU clusters can crack MD5 hashes at 200+ billion "
        "attempts/second. Rainbow tables provide instant lookups for common passwords."
    )
    fix_guidance = (
        "Use bcrypt, scrypt, or Argon2id for passwords (with appropriate cost factors). For data integrity "
        "checksums, use SHA-256 or SHA-3. Never use MD5/SHA1 for security purposes."
    )


class PlaintextPasswordInQueryRule(PatternRule):
    """Detects INSERT/UPDATE statements that appear to store plaintext passwords."""

    id = "SEC-CRYPTO-002"
    name = "Plaintext Password in Query"
    description = (
        "Detects INSERT/UPDATE statements that appear to store plaintext passwords (string literals assigned "
        "to password columns without hashing function)."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_CRYPTO

    pattern = r"\b(INSERT\s+INTO|UPDATE)\b[^;]*\b(password|passwd|pwd|secret_key|api_key|auth_token)\b[^;]*?(?:=\s*|VALUES\s*\()[^;(]*?['\"][^'\"()]{4,}['\"]"
    message_template = "Potential plaintext password detected in query: {match}"
    
    impact = (
        "Plaintext passwords in databases are catastrophic during breaches. A single leaked backup exposes "
        "all credentials. Violates every security compliance framework."
    )
    fix_guidance = (
        "Hash passwords at the application layer using bcrypt/Argon2id BEFORE SQL insertion. Never pass "
        "plaintext passwords through SQL. Store only the hash."
    )


class HardcodedEncryptionKeyRule(PatternRule):
    """Detects encryption/decryption functions with hardcoded key values."""

    id = "SEC-CRYPTO-003"
    name = "Hardcoded Encryption Key"
    description = "Detects encryption/decryption functions with hardcoded key values instead of key references."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_CRYPTO

    pattern = r"\b(AES_ENCRYPT|AES_DECRYPT|ENCRYPT|DECRYPT|ENCRYPTBYKEY|DECRYPTBYKEY|HASHBYTES|HMAC)\s*\([^)]*,\s*['\"][A-Za-z0-9\+/=!@#\$%^&\*\-]{8,}['\"]"
    message_template = "Hardcoded encryption key detected: {match}"
    
    impact = (
        "Hardcoded keys in queries appear in query logs, execution plans, source control history, and "
        "monitoring tools. Key compromise means total data compromise with no rotation path."
    )
    fix_guidance = (
        "Use HSM or dedicated key management (AWS KMS, Azure Key Vault, HashiCorp Vault). "
        "Reference keys by name/alias, never by value. Implement key rotation procedures."
    )


class WeakEncryptionAlgorithmRule(PatternRule):
    """Detects use of deprecated or weak encryption algorithms."""

    id = "SEC-CRYPTO-004"
    name = "Weak Encryption Algorithm"
    description = "Detects use of deprecated or weak encryption algorithms (DES, 3DES, RC4, Blowfish with small keys)."
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_CRYPTO

    pattern = r"\b(DES_ENCRYPT|DES_DECRYPT|TRIPLE_DES|3DES|RC4|RC2|BLOWFISH|IDEA)\s*\("
    message_template = "Weak encryption algorithm detected: {match}"
    
    impact = (
        "DES uses 56-bit keys, crackable in hours. RC4 has critical biases. These algorithms are prohibited "
        "by PCI-DSS, HIPAA, and most compliance frameworks."
    )
    fix_guidance = "Use AES-256-GCM for symmetric encryption. Migrate existing encrypted data to modern algorithms. Document encryption standards in security policy."


class PrivilegeEscalationRoleGrantRule(PatternRule):
    """Detects granting of high-privilege roles which may indicate privilege escalation attempts."""

    id = "SEC-AUTHZ-001"
    name = "Privilege Escalation via Role Grant"
    description = "Detects granting of high-privilege roles (admin, superuser, DBA) which may indicate privilege escalation attempts."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHORIZATION

    pattern = r"\b(GRANT|ALTER\s+ROLE|sp_addrolemember|ALTER\s+USER)\b[^;]+\b(admin|administrator|superuser|sysadmin|db_owner|dba|root|securityadmin|serveradmin|dbcreator|sa)\b"
    message_template = "High-privilege role grant detected: {match}"
    
    impact = (
        "Unrestricted admin access enables total database compromise. Attackers target privilege escalation as "
        "first step after initial access. Violates SOX segregation of duties."
    )
    fix_guidance = "Implement approval workflow for privilege grants. Use time-limited elevated access. Log all privilege changes. Review roles quarterly."


class SchemaOwnershipChangeRule(PatternRule):
    """Detects transfer of schema or object ownership."""

    id = "SEC-AUTHZ-002"
    name = "Schema Ownership Change"
    description = "Detects transfer of schema or object ownership, which can grant implicit permissions."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHORIZATION

    pattern = r"\b(ALTER\s+AUTHORIZATION\s+ON|ALTER\s+SCHEMA\s+\w+\s+TRANSFER|CHOWN|SET\s+OWNER)\b"
    message_template = "Schema ownership change detected: {match}"
    
    impact = (
        "Schema owners have implicit full control over all objects. Ownership transfer can bypass explicit "
        "DENY permissions and grant unexpected access."
    )
    fix_guidance = "Restrict ownership changes to DBA team only. Audit all authorization changes. Use explicit permissions instead of relying on ownership."


class HorizontalAuthorizationBypassRule(ASTRule):
    """Detects queries that access data without filtering by current user/tenant."""

    id = "SEC-AUTHZ-003"
    name = "Horizontal Authorization Bypass"
    description = (
        "Detects queries that access data without filtering by current user/tenant, "
        "suggesting potential horizontal privilege escalation."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHORIZATION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        # Tables that typically require user/tenant scoping
        sensitive_tables = {
            'orders', 'transactions', 'accounts', 'profiles', 'messages',
            'documents', 'files', 'payments', 'invoices', 'subscriptions',
            'user_data', 'customer_data', 'private_data'
        }
        
        # Columns that indicate proper scoping
        scoping_columns = {
            'user_id', 'tenant_id', 'account_id', 'owner_id', 'customer_id',
            'org_id', 'organization_id', 'created_by', 'belongs_to'
        }
        
        for node in ast.walk():
            if isinstance(node, exp.Select):
                tables = self._get_tables(ast)
                sensitive_found = set(tables) & sensitive_tables
                
                if sensitive_found:
                    # Check if WHERE clause includes scoping column
                    where_columns = self._get_where_columns(node)
                    has_scoping = bool(set(where_columns) & scoping_columns)
                    
                    if not has_scoping:
                        issues.append(
                            self.create_issue(
                                query=query,
                                message=f"Query on sensitive table(s) {sensitive_found} without user/tenant scoping",
                                snippet=str(node)[:100],
                                impact=(
                                    "Missing tenant isolation allows users to access other users' data. A single missing "
                                    "WHERE clause can expose entire customer database. Common cause of data breaches."
                                ),
                                fix=Fix(
                                    description="Always include user_id/tenant_id filter on multi-tenant data. Implement row-level security policies.",
                                    replacement="",
                                    is_safe=False,
                                ),
                            )
                        )
        
        return issues
        
    def _get_where_columns(self, node: Any) -> list[str]:
        columns = []
        where_node = getattr(node, "args", {}).get("where")
        if where_node:
            for col in where_node.find_all(exp.Column):
                columns.append(getattr(col, "name", "").lower())
        return columns


class SensitiveDataInErrorOutputRule(PatternRule):
    """Detects error handling statements that may expose sensitive column values."""

    id = "SEC-LOG-001"
    name = "Sensitive Data in Error Output"
    description = "Detects error handling statements (RAISERROR, THROW, PRINT) that may expose sensitive column values."
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_LOGGING

    pattern = r"\b(RAISERROR|THROW|RAISE|PRINT|DBMS_OUTPUT\.PUT_LINE|RAISE\s+NOTICE)\b[^;]*\b(password|pwd|ssn|social_security|credit_card|card_number|cvv|secret|token|api_key|private_key)\b"
    message_template = "Sensitive data exposed in error output: {match}"
    
    impact = (
        "Sensitive data in error messages may be logged, displayed to users, or sent to monitoring systems. "
        "Error logs often have weaker access controls than databases."
    )
    fix_guidance = "Use generic error messages for user-facing output. Log sensitive context only to secure audit logs with strict access controls. Mask sensitive values in all output."


class AuditTrailManipulationRule(PatternRule):
    """Detects attempts to modify, delete, or disable audit logs and trails."""

    id = "SEC-LOG-002"
    name = "Audit Trail Manipulation"
    description = "Detects attempts to modify, delete, or disable audit logs and trails."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_LOGGING

    pattern = r"\b(DELETE\s+FROM|TRUNCATE|UPDATE|DROP\s+TABLE)\s+[^;]*\b(audit|audit_log|audit_trail|event_log|security_log|access_log|change_log|history)\b|\b(SET\s+(?:sql_log_off|general_log|audit_trail|log_statement)\s*=\s*(?:0|OFF|NONE|false))\b"
    message_template = "Audit trail manipulation detected: {match}"
    
    impact = (
        "Audit log tampering destroys forensic capability and violates every compliance framework. "
        "Attackers delete logs to cover tracks. This is often evidence of active compromise."
    )
    fix_guidance = "Make audit tables append-only (no UPDATE/DELETE permissions). Use separate audit database with restricted access. Implement real-time log shipping to immutable storage."


class InsecureSessionTokenStorageRule(PatternRule):
    """Detects storage or retrieval of session tokens without apparent hashing."""

    id = "SEC-SESSION-001"
    name = "Insecure Session Token Storage"
    description = "Detects storage or retrieval of session tokens without apparent hashing, enabling session hijacking if database is compromised."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_SESSION

    pattern = r"\b(INSERT\s+INTO|UPDATE)\b[^;]*\b(session_token|auth_token|access_token|refresh_token|bearer_token|jwt_token)\b[^;]*?(?:=\s*|VALUES\s*\()[^;(]*?['\"]?[A-Za-z0-9_\-\.]{20,}['\"]?"
    message_template = "Insecure session token storage detected: {match}"
    
    impact = (
        "Unhashed session tokens in databases can be stolen and replayed. Database dumps, SQL injection, "
        "or backup exposure immediately compromises all active sessions."
    )
    fix_guidance = "Store only hashed tokens (SHA-256 is sufficient for tokens with high entropy). Compare using hash, not plaintext. Implement short token TTLs and secure rotation."


class SessionTimeoutNotEnforcedRule(PatternRule):
    """Detects session validation queries that don't check expiration timestamps."""

    id = "SEC-SESSION-002"
    name = "Session Timeout Not Enforced"
    description = "Detects session validation queries that don't check expiration timestamps."
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_SESSION

    pattern = r"\bSELECT\b[^;]*\bFROM\s+\w*(session|token)[s]?\b[^;]*\bWHERE\b(?!.*\b(expir|valid_until|expires_at|ttl|created_at)\b)"
    message_template = "Session timeout validation missing in query: {match}"
    
    impact = (
        "Sessions without expiration validation remain valid indefinitely. Stolen tokens provide permanent access. "
        "Violates security best practices and compliance requirements."
    )
    fix_guidance = "Always validate token expiration: WHERE token = ? AND expires_at > NOW(). Implement absolute timeouts (24h) and idle timeouts (30min). Force re-authentication for sensitive operations."


class UnboundedRecursiveCTERule(ASTRule):
    """Detects recursive CTEs without MAXRECURSION limits."""

    id = "SEC-DOS-001"
    name = "Unbounded Recursive CTE"
    description = "Detects recursive CTEs without MAXRECURSION limits, which can consume unlimited resources."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DOS

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            # Check for WITH RECURSIVE or recursive CTE pattern
            if isinstance(node, exp.With):
                for cte in node.expressions:
                    if isinstance(cte, exp.CTE):
                        # Check if CTE references itself (recursive)
                        cte_name = getattr(cte, "alias", "")
                        cte_query = getattr(cte, "this", None)
                        
                        if cte_name and cte_query and self._is_recursive(cte_query, cte_name):
                            # Check if OPTION (MAXRECURSION) exists in outer query
                            # This is a simplified check
                            query_str = query.raw.upper()
                            if 'MAXRECURSION' not in query_str:
                                issues.append(
                                    self.create_issue(
                                        query=query,
                                        message=f"Recursive CTE '{cte_name}' without MAXRECURSION limit",
                                        snippet=str(cte)[:100],
                                        impact=(
                                            "Unbounded recursion can consume all available memory and CPU. "
                                            "A malicious recursive CTE can crash the database server or trigger cloud cost explosion."
                                        ),
                                        fix=Fix(
                                            description="Always set MAXRECURSION: OPTION (MAXRECURSION 100). Design recursion with guaranteed termination conditions.",
                                            replacement="",
                                            is_safe=False,
                                        ),
                                    )
                                )
        
        return issues
        
    def _is_recursive(self, query_node: Any, cte_name: str) -> bool:
        """Check if CTE references itself"""
        for node in query_node.walk():
            if isinstance(node, exp.Table):
                name = getattr(node, "name", "")
                if name.lower() == cte_name.lower():
                    return True
        return False


class RegexDenialOfServiceRule(PatternRule):
    """Detects regular expressions with patterns known to cause catastrophic backtracking."""

    id = "SEC-DOS-002"
    name = "Regex Denial of Service (ReDoS)"
    description = "Detects regular expressions with patterns known to cause catastrophic backtracking."
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_DOS

    pattern = r"\b(REGEXP|RLIKE|REGEXP_LIKE|REGEXP_MATCHES|SIMILAR\s+TO)\s*\(?[^)]*(\(\?\:?\[?\w+\]\*\)[\*\+]|\(\.\*\)[\*\+]|\(\w\+\)[\*\+]|\[\^?\w+\]\*\[\^?\w+\]\*)"
    message_template = "Potential ReDoS pattern detected: {match}"
    
    impact = (
        "ReDoS patterns like (a+)+ or (.*)* can take exponential time on crafted input. "
        "A single malicious input can hang database threads for hours."
    )
    fix_guidance = "Use RE2-compatible patterns only (no backreferences, atomic groups). Set regex timeouts. Validate regex patterns before accepting user input."


class ImplicitTypeConversionRule(ASTRule):
    """Detects comparisons where column and value types likely mismatch."""

    id = "PERF-IDX-003"
    name = "Implicit Type Conversion on Indexed Column"
    description = (
        "Detects comparisons where column and value types likely mismatch, "
        "forcing implicit conversion that prevents index usage."
    )
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, exp.EQ):
                left = node.this
                right = getattr(node, "expression", None)
                
                if isinstance(left, exp.Column) and isinstance(right, exp.Literal):
                    col_name = left.name.lower()
                    
                    numeric_columns = {'id', 'user_id', 'account_id', 'order_id', 'product_id', 
                                       'amount', 'quantity', 'price', 'count', 'total', 'age'}
                    string_columns = {'name', 'email', 'phone', 'address', 'code', 'status',
                                      'type', 'category', 'description', 'title', 'sku'}
                    
                    is_string_literal = right.is_string
                    
                    if any(nc in col_name for nc in numeric_columns) and is_string_literal:
                        issues.append(self.create_issue(
                            query=query,
                            message=f"Implicit type conversion: numeric column '{left.name}' compared with string literal",
                            snippet=str(node)[:100],
                            impact=(
                                "Implicit type conversion (e.g., WHERE varchar_col = 123) forces SQL Server to convert every row, "
                                "turning index seeks into full scans. This is one of the most common hidden performance killers."
                            ),
                            fix=Fix(
                                description="Match literal types to column types. Use WHERE id = 123 not WHERE id = '123'.",
                                replacement="",
                                is_safe=False,
                            ),
                        ))
                    elif any(sc in col_name for sc in string_columns) and not is_string_literal:
                        issues.append(self.create_issue(
                            query=query,
                            message=f"Implicit type conversion: string column '{left.name}' compared with numeric literal",
                            snippet=str(node)[:100],
                            impact=(
                                "Implicit type conversion (e.g., WHERE varchar_col = 123) forces SQL Server to convert every row, "
                                "turning index seeks into full scans. This is one of the most common hidden performance killers."
                            ),
                            fix=Fix(
                                description="Match literal types to column types. For strings, always quote: WHERE status = 'active' not WHERE status = active.",
                                replacement="",
                                is_safe=False,
                            ),
                        ))
        
        return issues


class CompositeIndexOrderViolationRule(ASTRule):
    """Detects WHERE clauses that filter on non-leading columns of common composite index patterns."""

    id = "PERF-IDX-006"
    name = "Composite Index Column Order Violation"
    description = (
        "Detects WHERE clauses that filter on non-leading columns of common composite index patterns, "
        "preventing index seek."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        composite_patterns = {
            ('tenant_id', 'user_id'): 'tenant_id',
            ('tenant_id', 'created_at'): 'tenant_id',
            ('user_id', 'created_at'): 'user_id',
            ('account_id', 'transaction_date'): 'account_id',
            ('store_id', 'product_id'): 'store_id',
            ('category_id', 'subcategory_id'): 'category_id',
            ('parent_id', 'child_id'): 'parent_id',
            ('org_id', 'department_id'): 'org_id',
        }
        
        for node in ast.walk():
            if isinstance(node, exp.Select):
                where_cols = self._extract_where_columns(node)
                
                for (lead, secondary), required_lead in composite_patterns.items():
                    if secondary in where_cols and lead not in where_cols:
                        issues.append(self.create_issue(
                            query=query,
                            message=f"Filtering on '{secondary}' without leading column '{lead}' - composite index cannot be used efficiently",
                            snippet=str(node)[:100],
                            impact=(
                                "Composite indexes require the leading column in WHERE to enable index seek. "
                                "Filtering only on the secondary column forces a full index scan, often slower than a table scan."
                            ),
                            fix=Fix(
                                description="Include leading index columns in WHERE clause. Create additional indexes or reorder columns if needed.",
                                replacement="",
                                is_safe=False,
                            ),
                        ))
        
        return issues

    def _extract_where_columns(self, node: Any) -> set[str]:
        columns = set()
        where = getattr(node.args.get('where'), "this", node.args.get('where')) if node.args.get('where') else None
        if where:
            for col in where.find_all(exp.Column):
                columns.add(getattr(col, "name", "").lower())
        return columns


class NonSargableOrConditionRule(ASTRule):
    """Detects OR conditions across different columns that prevent index usage."""

    id = "PERF-IDX-007"
    name = "Non-SARGable OR Condition"
    description = "Detects OR conditions across different columns that prevent index usage (non-SARGable)."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, exp.Or):
                left_cols = self._get_columns(node.this)
                right_cols = self._get_columns(getattr(node, "expression", None))
                
                if left_cols and right_cols and left_cols != right_cols:
                    issues.append(self.create_issue(
                        query=query,
                        message=f"OR condition across different columns ({', '.join(left_cols)} OR {', '.join(right_cols)}) prevents index usage",
                        snippet=str(node)[:100],
                        impact="OR conditions across columns force the optimizer to scan all rows. Neither index can be fully utilized.",
                        fix=Fix(
                            description="Rewrite as UNION ALL of two queries, each using its own index.",
                            replacement="",
                            is_safe=False,
                        ),
                    ))
        
        return issues

    def _get_columns(self, node: Any) -> set[str]:
        columns = set()
        if node:
            for col in node.find_all(exp.Column):
                columns.add(getattr(col, "name", "").lower())
        return columns


class CoalesceOnIndexedColumnRule(PatternRule):
    """Detects functions wrapping indexed columns in WHERE clause."""

    id = "PERF-IDX-008"
    name = "COALESCE/ISNULL/NVL on Indexed Column"
    description = "Detects COALESCE, ISNULL, NVL, or IFNULL wrapping indexed columns in WHERE clause, which prevents index usage."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    pattern = r"(?i)\bWHERE\b[^;]*\b(COALESCE|ISNULL|NVL|NVL2|IFNULL)\s*\(\s*\w+"
    message_template = "Function wrapping column in WHERE clause prevents index seek: {match}"
    
    impact = (
        "Wrapping a column in COALESCE/ISNULL forces evaluation of every row. "
        "WHERE ISNULL(status, 'x') = 'active' cannot use an index on status."
    )
    fix_guidance = (
        "Handle NULL explicitly: WHERE (status = 'active' OR (status IS NULL AND 'x' = 'active')). "
        "Or use a filtered index, computed column, or ensure column is NOT NULL."
    )


class NegationOnIndexedColumnRule(ASTRule):
    """Detects NOT, !=, <> conditions that typically cannot use indexes efficiently."""

    id = "PERF-IDX-009"
    name = "Negation on Indexed Column (NOT, !=, <>)"
    description = "Detects NOT, !=, <> conditions that typically cannot use indexes efficiently."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_INDEX

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, exp.Not):
                issues.append(self.create_issue(
                    query=query,
                    message="NOT condition may prevent efficient index usage",
                    snippet=str(node)[:100],
                    impact=(
                        "Negation conditions force scanning all non-matching rows. "
                        "If 99% of rows match, you scan 99% of the table."
                    ),
                    fix=Fix(
                        description="Rewrite to positive condition if possible. Consider filtered indexes.",
                        replacement="",
                        is_safe=False,
                    ),
                ))
            
            if isinstance(node, exp.NEQ):
                issues.append(self.create_issue(
                    query=query,
                    message="Not-equal condition (<>, !=) typically cannot use index seek",
                    snippet=str(node)[:100],
                    impact=(
                        "Negation conditions typically prevent the query optimizer from performing efficient index seeks."
                    ),
                    fix=Fix(
                        description="Rewrite to IN or positive equality if values are known and limited.",
                        replacement="",
                        is_safe=False,
                    ),
                ))
        
        return issues


class TableLockHintRule(PatternRule):
    """Detects table-level lock hints that can cause severe blocking under concurrency."""

    id = "PERF-LOCK-001"
    name = "Table Lock Hint"
    description = "Detects table-level lock hints that can cause severe blocking under concurrency."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK

    pattern = r"(?i)\bWITH\s*\(\s*(TABLOCK|TABLOCKX|HOLDLOCK|XLOCK|PAGLOCK|ROWLOCK|UPDLOCK|SERIALIZABLE)\s*\)"
    message_template = "Extremely restrictive locking hint detected: {match}"
    
    impact = (
        "Table-level locks (TABLOCK, TABLOCKX) block ALL concurrent access to the table. "
        "Under load, this creates cascading waits that can freeze the entire application."
    )
    fix_guidance = "Remove table lock hints unless absolutely necessary. Use row-level locking (default behavior)."


class ReadUncommittedHintRule(PatternRule):
    """Detects NOLOCK or READ UNCOMMITTED hints that can return inconsistent data."""

    id = "PERF-LOCK-002"
    name = "NOLOCK / Read Uncommitted Hint"
    description = "Detects NOLOCK or READ UNCOMMITTED hints that can return inconsistent data."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK

    pattern = r"(?i)\bWITH\s*\(\s*(NOLOCK|READUNCOMMITTED)\s*\)|\bREAD\s+UNCOMMITTED\b|\bSET\s+TRANSACTION\s+ISOLATION\s+LEVEL\s+READ\s+UNCOMMITTED\b"
    message_template = "NOLOCK or READ UNCOMMITTED hint detected: {match}"
    
    impact = (
        "NOLOCK reads uncommitted data (dirty reads), can skip rows, read rows twice, "
        "or return phantom data. It's not 'faster' — it's 'wrong'."
    )
    fix_guidance = "Use READ COMMITTED SNAPSHOT ISOLATION (RCSI) for non-blocking reads without dirty reads."


class LongTransactionPatternRule(PatternRule):
    """Detects patterns indicating potentially long-running transactions that hold locks."""

    id = "PERF-LOCK-003"
    name = "Long Transaction Pattern"
    description = "Detects patterns indicating potentially long-running transactions that hold locks."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK

    pattern = r"(?i)\bBEGIN\s+(TRAN|TRANSACTION)\b[\s\S]{500,}?\b(COMMIT|ROLLBACK)\b"
    message_template = "Potentially long-running transaction detected (500+ characters)"
    
    impact = (
        "Long transactions hold locks for their entire duration, blocking other queries. "
        "A 10-second transaction holding a lock can queue up hundreds of waiting requests."
    )
    fix_guidance = "Keep transactions as short as possible. Do all preparation BEFORE BEGIN TRAN. Use optimistic concurrency."


class MissingTransactionIsolationRule(ASTRule):
    """Detects explicit transactions without isolation level specification."""

    id = "PERF-LOCK-004"
    name = "Missing Transaction Isolation Level"
    description = "Detects explicit transactions without isolation level specification, relying on default behavior."
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_LOCK

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        query_upper = query.raw.upper()
        
        has_begin_tran = 'BEGIN TRAN' in query_upper or 'BEGIN TRANSACTION' in query_upper
        has_isolation = 'ISOLATION LEVEL' in query_upper
        
        if has_begin_tran and not has_isolation:
            issues.append(self.create_issue(
                query=query,
                message="Transaction without explicit isolation level - behavior depends on server defaults",
                snippet=query.raw[:100],
                impact=(
                    "Default isolation levels vary by database and configuration. Code that works in development "
                    "may behave differently in production, causing subtle bugs or blocking."
                ),
                fix=Fix(
                    description="Explicitly set isolation level: SET TRANSACTION ISOLATION LEVEL READ COMMITTED.",
                    replacement="",
                    is_safe=False,
                ),
            ))
        
        return issues


class CursorDeclarationRule(PatternRule):
    """Detects CURSOR declarations, which indicate row-by-row processing."""

    id = "PERF-CURSOR-001"
    name = "Cursor Declaration"
    description = "Detects CURSOR declarations, which indicate row-by-row processing (RBAR - Row By Agonizing Row)."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_CURSOR

    pattern = r"(?i)\bDECLARE\s+\w+\s+CURSOR\b"
    message_template = "Cursor declaration detected: {match}"
    
    impact = (
        "Cursors process one row at a time, requiring round-trips and preventing set-based optimizations. "
        "Cursor operations are typically 10-100x slower than equivalent set-based SQL."
    )
    fix_guidance = "Rewrite using set-based operations: UPDATE...FROM, MERGE, window functions. If cursor is truly necessary, use FAST_FORWARD READ_ONLY."


class WhileLoopPatternRule(PatternRule):
    """Detects WHILE loops that may indicate row-by-row processing."""

    id = "PERF-CURSOR-002"
    name = "WHILE Loop Pattern"
    description = "Detects WHILE loops that may indicate row-by-row processing."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_CURSOR

    pattern = r"(?i)\bWHILE\s+[\(@].*\bBEGIN\b"
    message_template = "WHILE loop detected: {match}"
    
    impact = (
        "WHILE loops in SQL often indicate procedural thinking applied to a set-based language. "
        "Each iteration may execute separate queries, multiplying execution time."
    )
    fix_guidance = "Replace WHILE loops with set-based operations. Use recursive CTEs for hierarchical processing."


class NestedLoopJoinHintRule(PatternRule):
    """Detects LOOP JOIN hints that force nested loop joins."""

    id = "PERF-CURSOR-003"
    name = "Nested Loop Join Hint"
    description = "Detects LOOP JOIN hints that force nested loop joins, often inappropriate for large datasets."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_CURSOR

    pattern = r"(?i)\b(LOOP\s+JOIN|INNER\s+LOOP\s+JOIN|LEFT\s+LOOP\s+JOIN|OPTION\s*\(\s*LOOP\s+JOIN\s*\))"
    message_template = "Nested loop join hint detected: {match}"
    
    impact = (
        "Forced nested loop joins perform O(n*m) comparisons. For large tables, this is catastrophic. "
        "The optimizer usually knows better."
    )
    fix_guidance = "Remove join hints and let the optimizer choose. If hint is necessary, document why."


class LargeInClauseRule(ASTRule):
    """Detects IN clauses with excessive values (>50)."""

    id = "PERF-MEM-001"
    name = "Large IN Clause"
    description = "Detects IN clauses with excessive values (>50) that can cause memory pressure and poor plans."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, exp.In):
                values = getattr(node, "expressions", [])
                if not values and getattr(node, "query", None):
                    continue  # Subquery, not literal list
                
                if len(values) > 50:
                    issues.append(self.create_issue(
                        query=query,
                        message=f"IN clause with {len(values)} values - consider using temp table or table-valued parameter",
                        snippet=str(node)[:100],
                        impact=(
                            "Large IN clauses (100+ values) consume memory for query compilation, bloat the plan cache "
                            "with unique plans, and may force suboptimal execution strategies."
                        ),
                        fix=Fix(
                            description="Load values into a temp table or table-valued parameter (TVP), then JOIN.",
                            replacement="",
                            is_safe=False,
                        ),
                    ))
        
        return issues


class UnboundedTempTableRule(PatternRule):
    """Detects SELECT INTO temp table without WHERE clause or row limit."""

    id = "PERF-MEM-002"
    name = "Unbounded Temp Table Creation"
    description = "Detects SELECT INTO temp table without WHERE clause or row limit."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY

    pattern = r"(?i)\bSELECT\b[^;]*\bINTO\s+[#@]\w+\s+FROM\b(?!.*\b(WHERE|TOP|LIMIT)\b)"
    message_template = "Unbounded SELECT INTO temp table detected: {match}"
    
    impact = (
        "Unbounded SELECT INTO can fill tempdb, crash the instance, or exhaust memory. "
        "A single runaway query can impact all database users."
    )
    fix_guidance = "Always add WHERE clause or TOP/LIMIT to bound result size. Pre-create temp table with explicit schema for better memory estimation."


class OrderByWithoutLimitInSubqueryRule(ASTRule):
    """Detects ORDER BY in subqueries without LIMIT."""

    id = "PERF-MEM-003"
    name = "ORDER BY Without LIMIT in Subquery"
    description = "Detects ORDER BY in subqueries/CTEs without TOP/LIMIT, which is meaningless and wastes resources."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, exp.Subquery):
                inner = node.this
                if isinstance(inner, exp.Select):
                    has_order = inner.args.get('order') is not None
                    has_limit = inner.args.get('limit') is not None
                    
                    if has_order and not has_limit:
                        issues.append(self.create_issue(
                            query=query,
                            message="ORDER BY in subquery without LIMIT is meaningless and wastes resources",
                            snippet=str(inner)[:100],
                            impact=(
                                "Sorting requires memory allocation and CPU. ORDER BY without LIMIT in subqueries "
                                "does nothing (SQL standard ignores it) but still consumes resources."
                            ),
                            fix=Fix(
                                description="Remove ORDER BY from subqueries unless paired with TOP/LIMIT. Apply ordering in the final outer query only.",
                                replacement="",
                                is_safe=False,
                            ),
                        ))
        
        return issues


class GroupByHighCardinalityRule(ASTRule):
    """Detects GROUP BY on columns likely to have high cardinality (timestamps, IDs, UUIDs)."""

    id = "PERF-MEM-004"
    name = "GROUP BY on High-Cardinality Expression"
    description = "Detects GROUP BY on columns likely to have high cardinality (timestamps, IDs, UUIDs)."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_MEMORY

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        high_cardinality_patterns = {
            'timestamp', 'datetime', 'created_at', 'updated_at', 'modified_at',
            'uuid', 'guid', 'id', 'transaction_id', 'session_id', 'request_id',
            'email', 'phone', 'ip_address', 'user_agent'
        }
        
        for node in ast.walk():
            if isinstance(node, exp.Select):
                group = node.args.get('group')
                if group:
                    expressions = getattr(group, "expressions", [group])
                    for expr in expressions:
                        if isinstance(expr, exp.Column):
                            col_name = getattr(expr, "name", "").lower()
                            if any(hc in col_name for hc in high_cardinality_patterns):
                                issues.append(self.create_issue(
                                    query=query,
                                    message=f"GROUP BY on high-cardinality column '{expr.name}' - may create excessive groups",
                                    snippet=str(node)[:100],
                                    impact=(
                                        "Grouping by high-cardinality columns (timestamps, UUIDs) creates millions of groups, "
                                        "consuming massive memory and producing unusable results."
                                    ),
                                    fix=Fix(
                                        description="Truncate timestamps to meaningful intervals (e.g., DATE_TRUNC). Group by categorical columns.",
                                        replacement="",
                                        is_safe=False,
                                    ),
                                ))
        
        return issues


class QueryOptimizerHintRule(PatternRule):
    """Detects query hints that override optimizer decisions."""

    id = "PERF-HINT-001"
    name = "Query Optimizer Hint"
    description = "Detects query hints that override optimizer decisions."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_HINTS

    pattern = r"(?i)\bOPTION\s*\(\s*(FORCE\s+ORDER|HASH\s+JOIN|MERGE\s+JOIN|LOOP\s+JOIN|FAST\s+\d+|RECOMPILE|OPTIMIZE\s+FOR|MAXDOP|QUERYTRACEON|USE\s+PLAN)\b"
    message_template = "Query optimizer hint detected: {match}"
    
    impact = (
        "Query hints freeze execution plans. As data grows and distribution changes, hinted plans become suboptimal. "
        "Hints hide underlying issues (missing indexes, bad statistics)."
    )
    fix_guidance = "Remove hints and fix root cause: update statistics, add indexes, simplify query."


class IndexHintRule(PatternRule):
    """Detects forced index usage hints."""

    id = "PERF-HINT-002"
    name = "Index Hint"
    description = "Detects forced index usage hints."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_HINTS

    pattern = r"(?i)\b(FORCE\s+INDEX|USE\s+INDEX|IGNORE\s+INDEX|WITH\s*\(\s*INDEX\s*[=(])\b"
    message_template = "Index hint detected: {match}"
    
    impact = (
        "Index hints force specific index usage regardless of statistics. "
        "When data changes, the forced index may become suboptimal, but the hint remains."
    )
    fix_guidance = "Let the optimizer choose indexes. If it chooses wrong, update statistics or create better indexes."


class ParallelQueryHintRule(PatternRule):
    """Detects MAXDOP hints that override server parallelism settings."""

    id = "PERF-HINT-003"
    name = "Parallel Query Hint"
    description = "Detects MAXDOP hints that override server parallelism settings."
    severity = Severity.INFO
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_HINTS

    pattern = r"(?i)\bOPTION\s*\([^)]*MAXDOP\s+\d+"
    message_template = "Parallel query hint (MAXDOP) detected: {match}"
    
    impact = (
        "MAXDOP hints override server-level parallelism. MAXDOP 1 forces single-threaded execution. "
        "High MAXDOP values can starve other queries of CPU."
    )
    fix_guidance = "Use server or database-level MAXDOP settings. Per-query hints are rarely justified."


class ScalarUdfInQueryRule(PatternRule):
    """Detects scalar user-defined function calls in SELECT or WHERE clauses."""

    id = "PERF-SCALAR-001"
    name = "Scalar UDF in SELECT/WHERE"
    description = "Detects scalar user-defined function calls in SELECT or WHERE clauses."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_EXECUTION

    pattern = r"(?i)\b(SELECT|WHERE)\b[^;]*\bdbo\.\w+\s*\([^)]*\)"
    message_template = "Scalar UDF detected: {match}"
    
    impact = (
        "Scalar UDFs execute row-by-row, prevent parallelism, and cannot be inlined in most SQL versions. "
        "A single scalar UDF can make queries 100x slower."
    )
    fix_guidance = "Rewrite as inline table-valued function (iTVF) or move logic to application layer."


class CorrelatedSubqueryRule(ASTRule):
    """Detects correlated subqueries that execute once per outer row."""

    id = "PERF-SCALAR-002"
    name = "Correlated Subquery"
    description = "Detects correlated subqueries that execute once per outer row."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_EXECUTION

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, exp.Select):
                for subq in node.find_all(exp.Subquery):
                    inner = subq.this
                    if isinstance(inner, exp.Select):
                        outer_tables = self._get_table_aliases(node)
                        inner_refs = self._get_column_table_refs(inner)
                        
                        if outer_tables and inner_refs and (outer_tables & inner_refs):
                            issues.append(self.create_issue(
                                query=query,
                                message="Correlated subquery executes once per outer row - consider rewriting as JOIN",
                                snippet=str(subq)[:100],
                                impact=(
                                    "Correlated subqueries execute for every row in the outer query. "
                                    "For 1 million outer rows, the subquery runs 1 million times."
                                ),
                                fix=Fix(
                                    description="Rewrite as JOIN or use window functions.",
                                    replacement="",
                                    is_safe=False,
                                ),
                            ))
        
        return issues

    def _get_table_aliases(self, node: Any) -> set[str]:
        aliases = set()
        for table in node.find_all(exp.Table):
            if table.alias:
                aliases.add(table.alias.lower())
            elif getattr(table, "name", None):
                aliases.add(getattr(table, "name", "").lower())
        return aliases

    def _get_column_table_refs(self, node: Any) -> set[str]:
        refs = set()
        for col in node.find_all(exp.Column):
            if col.table:
                refs.add(col.table.lower())
        return refs


class OrderByNonIndexedColumnRule(ASTRule):
    """Detects ORDER BY on columns unlikely to be indexed."""

    id = "PERF-SORT-001"
    name = "ORDER BY on Non-Indexed Column"
    description = "Detects ORDER BY on columns unlikely to be indexed, forcing expensive sorts."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_SORT

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        unlikely_indexed = {
            'description', 'notes', 'comments', 'body', 'content', 'message',
            'address', 'bio', 'about', 'metadata', 'json_data', 'xml_data',
            'calculated', 'computed', 'derived'
        }
        
        for node in ast.walk():
            if isinstance(node, exp.Select):
                order = node.args.get('order')
                if order:
                    expressions = getattr(order, "expressions", [order])
                    for expr in expressions:
                        if isinstance(expr, exp.Ordered):
                            col = expr.this
                            if isinstance(col, exp.Column):
                                col_name = getattr(col, "name", "").lower()
                                if any(ui in col_name for ui in unlikely_indexed):
                                    issues.append(self.create_issue(
                                        query=query,
                                        message=f"ORDER BY on likely non-indexed column '{col.name}' - may require expensive sort",
                                        snippet=str(node)[:100],
                                        impact=(
                                            "Sorting without index support requires loading all rows into memory, sorting, then returning. "
                                            "For large tables, this spills to disk (tempdb), dramatically slowing queries."
                                        ),
                                        fix=Fix(
                                            description="Create covering index including ORDER BY columns. Or add index on frequently sorted columns.",
                                            replacement="",
                                            is_safe=False,
                                        ),
                                    ))
        
        return issues


class LargeUnbatchedOperationRule(ASTRule):
    """Detects UPDATE/DELETE without WHERE clause or row limit."""

    id = "PERF-BATCH-001"
    name = "Large Unbatched Operation"
    description = "Detects UPDATE/DELETE without WHERE clause or row limit, affecting entire tables."
    severity = Severity.HIGH
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_BATCH

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, (exp.Update, exp.Delete)):
                query_upper = query.raw.upper()
                has_limit = 'TOP' in query_upper or 'LIMIT' in query_upper
                
                if not has_limit:
                    stmt_type = 'UPDATE' if isinstance(node, exp.Update) else 'DELETE'
                    issues.append(self.create_issue(
                        query=query,
                        message=f"Unbatched {stmt_type} without WHERE clause - affects entire table",
                        snippet=str(node)[:100],
                        impact=(
                            "Unbatched mass operations generate massive transaction logs, hold locks for extended periods, "
                            "and can fill disk. A single DELETE can lock a table for hours."
                        ),
                        fix=Fix(
                            description="Process in batches using TOP/LIMIT and loops. Use WAITFOR DELAY between batches.",
                            replacement="",
                            is_safe=False,
                        ),
                    ))
        
        return issues


class MissingBatchSizeInLoopRule(PatternRule):
    """Detects WHILE loops with UPDATE/DELETE that don't specify TOP/LIMIT."""

    id = "PERF-BATCH-002"
    name = "Missing Batch Size in Loop"
    description = "Detects WHILE loops with UPDATE/DELETE that don't specify TOP/LIMIT."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_BATCH

    pattern = r"(?i)\bWHILE\b[\s\S]*?\b(UPDATE|DELETE)\b(?![\s\S]*?\b(TOP|LIMIT)\b)[\s\S]*?\bEND\b"
    message_template = "WHILE loop with unbatched DML detected."
    
    impact = (
        "WHILE loops without batch limits may process unlimited rows per iteration, "
        "negating the benefits of batching."
    )
    fix_guidance = "Always use TOP/LIMIT in batched operations inside loops."


class ExcessiveColumnCountRule(ASTRule):
    """Detects SELECT statements with more than 20 explicit columns."""

    id = "PERF-NET-001"
    name = "Excessive Column Count in SELECT"
    description = "Detects SELECT statements with more than 20 explicit columns."
    severity = Severity.LOW
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_NETWORK

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        for node in ast.walk():
            if isinstance(node, exp.Select):
                columns = getattr(node, "expressions", [])
                
                if any(isinstance(c, exp.Star) for c in columns):
                    continue
                
                if len(columns) > 20:
                    issues.append(self.create_issue(
                        query=query,
                        message=f"SELECT with {len(columns)} columns - consider reducing or using separate queries",
                        snippet=str(node)[:100],
                        impact=(
                            "Wide result sets waste network bandwidth, consume more memory on both server and client, "
                            "and often indicate missing projection."
                        ),
                        fix=Fix(
                            description="Select only needed columns. Use DTOs/projections in application layer.",
                            replacement="",
                            is_safe=False,
                        ),
                    ))
        
        return issues


class LargeObjectUnboundedRule(ASTRule):
    """Detects SELECT of BLOB/CLOB/TEXT columns without WHERE clause."""

    id = "PERF-NET-002"
    name = "Large Object Column in Non-Filtered Query"
    description = "Detects SELECT of BLOB/CLOB/TEXT columns without WHERE clause, potentially transferring massive data."
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_NETWORK

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        
        blob_columns = {
            'blob', 'clob', 'text', 'content', 'body', 'data', 'image', 
            'document', 'file', 'attachment', 'payload', 'binary'
        }
        
        for node in ast.walk():
            if isinstance(node, exp.Select):
                has_where = node.args.get('where') is not None
                has_limit = node.args.get('limit') is not None
                
                if not has_where and not has_limit:
                    for col in getattr(node, "expressions", []):
                        if isinstance(col, exp.Column):
                            col_name = getattr(col, "name", "").lower()
                            if any(bc in col_name for bc in blob_columns):
                                issues.append(self.create_issue(
                                    query=query,
                                    message=f"Unbounded SELECT of large object column '{col.name}'",
                                    snippet=str(node)[:100],
                                    impact=(
                                        "Selecting BLOB columns without filtering can transfer gigabytes of data. "
                                        "Each BLOB read may hit slow storage. This crashes applications and saturates networks."
                                    ),
                                    fix=Fix(
                                        description="Exclude large columns from general queries. Fetch BLOB data separately by ID when needed.",
                                        replacement="",
                                        is_safe=False,
                                    ),
                                ))
        
        return issues


# =============================================================================
# CATALOG EXPORT
# =============================================================================


def get_all_rules() -> list[Rule]:
    """
    Get instances of all built-in rules.

    Returns:
        List of Rule objects.
    """
    return [
        SQLInjectionRule(),
        HardcodedPasswordRule(),
        GrantAllRule(),
        SelectStarRule(),
        LeadingWildcardRule(),
        MissingWhereRule(),
        DistinctOnLargeSetRule(),
        FunctionOnIndexedColumnRule(),
        OrOnIndexedColumnsRule(),
        DeepOffsetPaginationRule(),
        CartesianProductRule(),
        TooManyJoinsRule(),
        UnfilteredAggregationRule(),
        OrderByInSubqueryRule(),
        UnboundedSelectRule(),
        NotInSubqueryRule(),
        UnsafeWriteRule(),
        DropTableRule(),
        TruncateWithoutTransactionRule(),
        AlterTableDestructiveRule(),
        MissingRollbackRule(),
        AutocommitDisabledRule(),
        ExceptionSwallowedRule(),
        LongTransactionWithoutSavepointRule(),
        PIIExposureRule(),
        UnencryptedSensitiveColumnRule(),
        RetentionPolicyMissingRule(),
        CrossBorderDataTransferRule(),
        RightToErasureRule(),
        AuditLogTamperingRule(),
        ConsentTableMissingRule(),
        ImplicitJoinRule(),
        NullComparisonRule(),
        SelectWithoutFromRule(),
        HardcodedDateRule(),
        WildcardInColumnListRule(),
        DuplicateConditionRule(),
        UnionWithoutAllRule(),
        MissingAliasRule(),
        CommentedCodeRule(),
        DynamicSQLExecutionRule(),
        TautologicalOrConditionRule(),
        TimeBasedBlindInjectionRule(),
        GrantToPublicRule(),
        UserCreationWithoutPasswordRule(),
        PasswordPolicyBypassRule(),
        DataExfiltrationViaFileRule(),
        RemoteDataAccessRule(),
        DangerousServerConfigRule(),
        OverprivilegedExecutionContextRule(),
        FullTableScanRule(),
        ExpensiveWindowFunctionRule(),
        SelectStarInETLRule(),
        RedundantOrderByRule(),
        CrossRegionDataTransferCostRule(),

        SecondOrderSQLInjectionRule(),
        LikeWildcardInjectionRule(),
        WeakHashingAlgorithmRule(),
        PlaintextPasswordInQueryRule(),
        HardcodedEncryptionKeyRule(),
        WeakEncryptionAlgorithmRule(),
        PrivilegeEscalationRoleGrantRule(),
        SchemaOwnershipChangeRule(),
        HorizontalAuthorizationBypassRule(),
        SensitiveDataInErrorOutputRule(),
        AuditTrailManipulationRule(),
        InsecureSessionTokenStorageRule(),
        SessionTimeoutNotEnforcedRule(),
        UnboundedRecursiveCTERule(),
        RegexDenialOfServiceRule(),

        ImplicitTypeConversionRule(),
        CompositeIndexOrderViolationRule(),
        NonSargableOrConditionRule(),
        CoalesceOnIndexedColumnRule(),
        NegationOnIndexedColumnRule(),
        TableLockHintRule(),
        ReadUncommittedHintRule(),
        LongTransactionPatternRule(),
        MissingTransactionIsolationRule(),
        CursorDeclarationRule(),
        WhileLoopPatternRule(),
        NestedLoopJoinHintRule(),
        LargeInClauseRule(),
        UnboundedTempTableRule(),
        OrderByWithoutLimitInSubqueryRule(),
        GroupByHighCardinalityRule(),
        QueryOptimizerHintRule(),
        IndexHintRule(),
        ParallelQueryHintRule(),
        ScalarUdfInQueryRule(),
        CorrelatedSubqueryRule(),
        OrderByNonIndexedColumnRule(),
        LargeUnbatchedOperationRule(),
        MissingBatchSizeInLoopRule(),
        ExcessiveColumnCountRule(),
        LargeObjectUnboundedRule(),
    ]
