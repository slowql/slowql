from __future__ import annotations

"""
Reliability Timeouts rules.
"""

from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'LongRunningQueryRiskRule',
    'MissingRetryLogicRule',
    'StaleReadRiskRule',
]


class LongRunningQueryRiskRule(ASTRule):
    """Detects potentially long-running queries without bounds."""

    id = "REL-TIMEOUT-001"
    name = "Long-Running Query Risk"
    description = (
        "Detects queries with multiple JOINs, subqueries, and no LIMIT that may run "
        "indefinitely without timeout protection."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_TIMEOUT

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, exp.Select):
                # Count complexity factors
                joins = node.args.get("joins") or []
                join_count = len(joins)

                # Count subqueries
                subquery_count = len(list(node.find_all(exp.Subquery)))

                # Check for LIMIT/TOP
                has_limit = node.args.get("limit") is not None
                query_upper = query.raw.upper()
                has_top = "TOP" in query_upper
                has_timeout = "TIMEOUT" in query_upper or "MAXTIME" in query_upper

                complexity = join_count + subquery_count

                if complexity >= 3 and not (has_limit or has_top or has_timeout):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"Complex query ({join_count} JOINs, {subquery_count} subqueries) without row limit or timeout.",
                            snippet=str(node)[:100],
                        )
                    )
        return issues

    impact = (
        "Complex queries without bounds can run for hours, consuming connections, "
        "blocking resources, and exhausting timeout-less connection pools."
    )
    fix_guidance = (
        "Add LIMIT/TOP to bound result size. Set query timeout at connection level. "
        "Use query governor or Resource Governor. Monitor and kill long-running queries."
    )


class StaleReadRiskRule(PatternRule):
    """Detects immediate reads after writes without transactions."""

    id = "REL-STALE-001"
    name = "Stale Read Risk"
    description = (
        "Detects UPDATE/INSERT followed by immediate SELECT without transaction, "
        "which may return stale data in replicated/distributed environments."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_CONSISTENCY

    pattern = r"^(?!.*?\bBEGIN\b).*?(INSERT|UPDATE)\s+[^;]+;\s*SELECT\s+[^;]+FROM\s+(\w+)"
    message_template = "Potential stale read: SELECT immediately follows UPDATE/INSERT without transaction."

    impact = (
        "In replicated databases, writes go to primary, reads may hit replicas. SELECT "
        "immediately after UPDATE may return old data if replication lag exists."
    )
    fix_guidance = (
        "Wrap write-then-read in transaction. Use read-from-primary hints for critical "
        "reads. Use RETURNING/OUTPUT clause to get written data atomically. Accept "
        "eventual consistency where appropriate."
    )


class MissingRetryLogicRule(PatternRule):
    """Detects transaction blocks without apparent retry logic."""

    id = "REL-RETRY-001"
    name = "Missing Retry Logic"
    description = (
        "Detects transaction blocks without error handling or retry patterns, which "
        "will fail permanently on transient errors."
    )
    severity = Severity.INFO
    dimension = Dimension.RELIABILITY
    category = Category.REL_RETRY

    pattern = (
        r"\bBEGIN\s+(TRAN|TRANSACTION)\b(?![\s\S]*\b(TRY|CATCH|EXCEPTION|RETRY|"
        r"ATTEMPT|LOOP|WHILE)\b)[\s\S]*?\b(COMMIT|ROLLBACK)\b"
    )
    message_template = "Transaction block without retry logic — will fail on transient errors."

    impact = (
        "Transactions fail on transient errors (deadlock, timeout, connection blip). "
        "Without retry logic, operations fail permanently when they could succeed on retry."
    )
    fix_guidance = (
        "Implement retry loop with exponential backoff for deadlocks (error 1205) and "
        "timeouts. Use TRY...CATCH block. Limit retry attempts (3-5). Log failures "
        "for monitoring."
    )
