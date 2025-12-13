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

import re
from typing import Any

from slowql.core.models import (
    Category,
    Dimension,
    Fix,
    Issue,
    Severity,
)
from slowql.core.models import Query
from slowql.rules.base import ASTRule, PatternRule, Rule

# =============================================================================
# 🔒 SECURITY RULES
# =============================================================================


class SQLInjectionRule(PatternRule):
    """Detects potential SQL injection via string concatenation."""

    id = "SEC-INJ-001"
    name = "Potential SQL Injection"
    description = "Detects string concatenation in SQL queries which may indicate SQL injection vulnerabilities."
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION
    
    # Matches: 'SELECT ' + var + ' FROM' or "SELECT " + var
    pattern = r"(?i)(['\"]\s*\+\s*[a-zA-Z_]\w*)|([a-zA-Z_]\w*\s*\+\s*['\"])"
    message_template = "Potential SQL injection detected: String concatenation with variable '{match}'."
    
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
        from sqlglot import exp
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
                issues.append(self.create_issue(
                    query=query,
                    message="GRANT ALL detected. Follow principle of least privilege.",
                    snippet=query.raw,
                    impact="Users receive administrative control, increasing blast radius of compromise.",
                ))
                
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
        from sqlglot import exp
        issues = []
        
        if query.is_select:
            # Check for star in projections
            for expression in ast.find_all(exp.Star):
                # Ensure it's in the projection list (not count(*))
                parent = expression.parent
                if isinstance(parent, exp.Select):
                    issues.append(self.create_issue(
                        query=query,
                        message="Avoid 'SELECT *'. Explicitly list required columns.",
                        snippet="SELECT *",
                        fix=Fix(
                            description="Replace * with specific column names",
                            replacement="SELECT col1, col2 ...", # Placeholder logic
                            is_safe=False # Cannot safely auto-fix without schema
                        ),
                        impact="Increases network traffic, memory usage, and prevents covering index usage."
                    ))
                    break # Report once per query
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
    fix_guidance = "Use Full-Text Search (e.g., Elasticsearch, Postgres FTS) for substring searches."


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
        from sqlglot import exp
        
        if query.query_type not in ("UPDATE", "DELETE"):
            return []

        # Check for WHERE clause
        if not ast.find(exp.Where):
            return [self.create_issue(
                query=query,
                message=f"Unbounded {query.query_type} detected (missing WHERE).",
                snippet=query.raw[:50],
                impact=f"Will modify/delete ALL rows in the table, causing massive lock contention and log growth.",
            )]
        
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
        from sqlglot import exp
        
        if isinstance(ast, exp.Select) and ast.args.get("distinct"):
            return [self.create_issue(
                query=query,
                message="DISTINCT usage detected. Ensure this is necessary.",
                snippet="SELECT DISTINCT ...",
                impact="Requires sorting or hashing entire result set. Check if data model allows duplicates."
            )]
        return []


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
        from sqlglot import exp
        
        if query.query_type not in ("DELETE", "UPDATE"):
            return []

        if not ast.find(exp.Where):
             # Logic to distinguish TRUNCATE intent vs Accidental Delete
            fix_suggestion = "Use TRUNCATE TABLE if you intend to wipe the table." if query.query_type == "DELETE" else "Add a WHERE clause."
            
            return [self.create_issue(
                query=query,
                message=f"CRITICAL: {query.query_type} statement has no WHERE clause.",
                snippet=query.raw,
                severity=Severity.CRITICAL,
                fix=Fix(
                    description="Add WHERE clause placeholder",
                    replacement=f"{query.raw.rstrip(';')} WHERE id = ...;",
                    is_safe=False
                ),
                impact="Instant data loss of entire table content."
            )]
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
        from sqlglot import exp
        if isinstance(ast, exp.Drop):
            return [self.create_issue(
                query=query,
                message="DROP statement detected.",
                snippet=query.raw,
                impact="Irreversible schema and data destruction. Ensure this is a migration script."
            )]
        return []


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
        from sqlglot import exp
        
        if not query.is_select:
            return []

        # Check if FROM has multiple tables in the same From node (comma separation)
        from_clause = ast.find(exp.From)
        if from_clause and len(from_clause.expressions) > 1:
             return [self.create_issue(
                query=query,
                message="Implicit join syntax detected (comma-separated tables).",
                snippet=str(from_clause),
                fix=Fix(
                    description="Convert to explicit INNER JOIN",
                    replacement="... FROM table1 JOIN table2 ON ...",
                    is_safe=False
                ),
                impact="Implicit joins are harder to read and prone to accidental cross-joins."
            )]
        return []


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