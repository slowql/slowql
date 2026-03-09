from __future__ import annotations

"""
Security Injection rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'DynamicSQLExecutionRule',
    'JSONFunctionInjectionRule',
    'LDAPInjectionRule',
    'LikeWildcardInjectionRule',
    'NoSQLInjectionRule',
    'SQLInjectionRule',
    'SecondOrderSQLInjectionRule',
    'ServerSideTemplateInjectionRule',
    'TautologicalOrConditionRule',
    'TimeBasedBlindInjectionRule',
    'XMLXPathInjectionRule',
]


class SQLInjectionRule(PatternRule):
    """Detects potential SQL injection via string concatenation."""

    id = "SEC-INJ-001"
    name = "Potential SQL Injection"
    description = "Detects string concatenation in SQL queries which may indicate SQL injection."
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r"(['\"]\s*\+\s*[a-zA-Z_]\w*)|([a-zA-Z_]\w*\s*\+\s*['\"])"
    message_template = (
        "Potential SQL injection detected: String concatenation with variable '{match}'."
    )

    impact = "Attackers can execute arbitrary SQL commands, accessing or destroying data."
    rationale = "Dynamic SQL construction using concatenation is the #1 vector for SQL injection."
    fix_guidance = "Use parameterized queries (prepared statements) instead of concatenation."
    references = ("https://owasp.org/www-community/attacks/SQL_Injection",)


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


class LDAPInjectionRule(PatternRule):
    """Detects LDAP filter construction using string concatenation with user input."""

    id = "SEC-INJ-007"
    name = "LDAP Injection in Directory Queries"
    description = (
        "Detects LDAP filter construction using string concatenation with user input, "
        "enabling LDAP injection attacks."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r'\b(LDAP|AD_|DIRECTORY)\w*\s*\([^)]*(\+|CONCAT|CONCATENATE|\|\|)[^)]*\b(cn=|ou=|dc=|uid=|objectClass=)\b'

    impact = (
        "LDAP injection allows attackers to bypass authentication, enumerate directory structure, "
        "and access unauthorized data. Concatenating user input into LDAP filters enables filter "
        "manipulation like SQL injection."
    )
    fix_guidance = (
        "Use parameterized LDAP queries. Escape special characters: *()\\NULL. Validate input against "
        "whitelist. Use prepared LDAP statements where available. Example: escape * as \\2a, ( as \\28."
    )


class NoSQLInjectionRule(PatternRule):
    """Detects JSON/document queries with concatenated input for NoSQL injection."""

    id = "SEC-INJ-008"
    name = "NoSQL Injection Pattern"
    description = (
        "Detects JSON/document queries with concatenated input that may enable NoSQL injection "
        "in document databases."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r'\b(OPENJSON|JSON_QUERY|JSON_VALUE|FOR\s+JSON|MONGODB|COSMOSDB|mongo_\w*|json_\w*)\b[^;]*(\+|CONCAT|\|\|)[^;]*[{}\[\]$]'

    impact = (
        "NoSQL injection in JSON queries allows filter bypass, data extraction, and denial of service. "
        "MongoDB-style operators like $where, $ne can be injected to bypass authentication."
    )
    fix_guidance = (
        "Parameterize JSON queries. Use ORM/ODM libraries with prepared statements. Validate JSON structure. "
        "Never concatenate user input into JSON filter strings. Example: use parameterized MongoDB queries, "
        "not string concatenation."
    )


class XMLXPathInjectionRule(PatternRule):
    """Detects XPath/XQuery construction using string concatenation."""

    id = "SEC-INJ-009"
    name = "XML/XPath Injection"
    description = (
        "Detects XPath/XQuery construction using string concatenation, enabling XML injection attacks."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r'\b(XMLQUERY|XMLEXISTS|XPATH|XQUERY|xml_)\b[^;]*(\+|CONCAT|\|\|)[^;]*[/\[\]]'

    impact = (
        "XPath injection allows attackers to manipulate XML queries, bypass authentication, and extract "
        "unauthorized data from XML documents. Similar to SQL injection but for XML."
    )
    fix_guidance = (
        "Use parameterized XPath/XQuery. Escape XML special characters: < > & ' \". Validate against "
        "schema. Use XPath variables instead of concatenation. Example: use $variable in XPath, "
        "not string concatenation."
    )


class ServerSideTemplateInjectionRule(PatternRule):
    """Detects template engine usage with user input for SSTI."""

    id = "SEC-INJ-010"
    name = "Server-Side Template Injection"
    description = (
        "Detects template engine usage with user input, which may enable server-side template "
        "injection (SSTI)."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r'\b(RENDER|TEMPLATE|EVAL|EXECUTE|PROCESS|render_)\w*\b\([^)]*(\+|CONCAT|\|\|)'

    impact = (
        "Template injection allows arbitrary code execution on the server. If user input is embedded "
        "in template syntax ({{}}, {%%}), attackers can execute system commands."
    )
    fix_guidance = (
        "Never use user input in template strings. Use static templates only. If dynamic content is "
        "needed, use safe interpolation methods. Escape template syntax characters. Sandbox template execution."
    )


class JSONFunctionInjectionRule(PatternRule):
    """Detects JSON path expressions built via concatenation."""

    id = "SEC-INJ-011"
    name = "SQL Injection via JSON Functions"
    description = (
        "Detects JSON path expressions built via concatenation, which can enable injection through "
        "JSON query functions."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r'\b(JSON_OBJECT|JSON_ARRAY|JSON_INSERT|JSON_REPLACE|JSON_SET|json_\w*)\b[^;]*(\+|CONCAT|\|\|)'

    impact = (
        "Concatenating user input into JSON path expressions allows attackers to modify query logic, "
        "access unauthorized data, or cause errors that reveal schema information."
    )
    fix_guidance = (
        "Use parameterized JSON paths. Validate path components against whitelist. Avoid dynamic path "
        "construction. Example: validate that path only contains allowed property names before using."
    )
