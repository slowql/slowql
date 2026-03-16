"""
Security Dos rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    "PgSleepUsageRule",
    "PgSleepUsageRule",
    "RegexDenialOfServiceRule",
    "TsqlWaitforDelayRule",
    "UnboundedRecursiveCTERule",
]


class UnboundedRecursiveCTERule(ASTRule):
    """Detects recursive CTEs without MAXRECURSION limits."""

    id = "SEC-DOS-001"
    name = "Unbounded Recursive CTE"
    description = (
        "Detects recursive CTEs without MAXRECURSION limits, which can consume unlimited resources."
    )
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
                            if "MAXRECURSION" not in query_str:
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
    description = (
        "Detects regular expressions with patterns known to cause catastrophic backtracking."
    )
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


class PgSleepUsageRule(PatternRule):
    """Detects pg_sleep() calls which may indicate DoS vectors or testing artifacts."""

    id = "SEC-PG-001"
    name = "pg_sleep Usage Detected"
    description = (
        "Detects calls to pg_sleep() which is a PostgreSQL-specific function. "
        "In production code this is almost always a testing artifact or a "
        "deliberate denial-of-service vector used to verify blind SQL injection."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_DOS
    dialects = ("postgresql",)

    pattern = r"\bpg_sleep\s*\("
    message_template = "pg_sleep() call detected — potential DoS vector or testing artifact: {match}"

    impact = (
        "pg_sleep() ties up a database connection for the specified duration. "
        "An attacker can use it to confirm blind SQL injection or exhaust the "
        "connection pool, causing denial of service."
    )
    fix_guidance = (
        "Remove pg_sleep() calls from production code. If used for testing, "
        "guard behind a feature flag or test-only configuration."
    )


class TsqlWaitforDelayRule(PatternRule):
    """Detects WAITFOR DELAY in T-SQL production code."""

    id = "PERF-TSQL-004"
    name = "WAITFOR DELAY in Production Code"
    description = (
        "WAITFOR DELAY pauses execution for the specified duration. In "
        "production code this is almost always a testing artifact or a "
        "blind SQL injection indicator."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    category = Category.PERF_EXECUTION
    dialects = ("tsql",)

    pattern = r"\bWAITFOR\s+DELAY\b"
    message_template = "WAITFOR DELAY detected — testing artifact or blind injection vector: {match}"

    impact = (
        "WAITFOR DELAY ties up a connection and worker thread for the "
        "specified duration. An attacker can use it to confirm blind "
        "SQL injection or exhaust the connection pool."
    )
    fix_guidance = (
        "Remove WAITFOR DELAY from production code. If used for polling, "
        "use Service Broker or Query Notification instead."
    )
