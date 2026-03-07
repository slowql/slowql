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
# CATALOG EXPORT
# =============================================================================


def get_all_rules() -> list[Rule]:
    """
    Get instances of all built-in rules.

    Returns:
        List of Rule objects.
    """
    return [
        # Security
        SQLInjectionRule(),
        HardcodedPasswordRule(),
        GrantAllRule(),
        # Performance
        SelectStarRule(),
        LeadingWildcardRule(),
        MissingWhereRule(),
        DistinctOnLargeSetRule(),
        # Reliability
        UnsafeWriteRule(),
        DropTableRule(),
        # Compliance
        PIIExposureRule(),
        # Quality
        ImplicitJoinRule(),
    ]
