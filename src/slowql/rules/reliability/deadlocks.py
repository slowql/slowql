"""
Reliability Deadlocks rules.
"""

from __future__ import annotations

from typing import Any

from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'DeadlockPatternRule',
    'LockEscalationRiskRule',
]


class DeadlockPatternRule(PatternRule):
    """Detects transactions that update multiple tables in potentially inconsistent order."""

    id = "REL-DEAD-001"
    name = "Deadlock Pattern"
    description = (
        "Detects transactions that update multiple tables, which can cause deadlocks if "
        "other transactions update the same tables in different order."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DEADLOCK

    pattern = r"\bBEGIN\b[\s\S]*?\bUPDATE\s+(\w+)\b[\s\S]*?\bUPDATE\s+(?!\1)(\w+)\b[\s\S]*?\bCOMMIT\b"
    message_template = "Potential deadlock pattern: Multiple table updates within a transaction."

    impact = (
        "Deadlocks occur when Transaction A locks Table1 then waits for Table2, while "
        "Transaction B locks Table2 then waits for Table1. Both freeze, one must abort."
    )
    fix_guidance = (
        "Always lock tables in consistent alphabetical order across all transactions. "
        "Use SELECT ... FOR UPDATE in consistent order. Consider using NOWAIT and "
        "retry logic."
    )


class LockEscalationRiskRule(ASTRule):
    """Detects UPDATE/DELETE statements with lock escalation risk."""

    id = "REL-DEAD-002"
    name = "Lock Escalation Risk"
    description = (
        "Detects UPDATE/DELETE without WHERE clause or with unbounded conditions "
        "that may lock excessive rows, causing lock escalation and blocking."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.RELIABILITY
    category = Category.REL_DEADLOCK

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        for node in ast.walk():
            if isinstance(node, (exp.Update, exp.Delete)):
                where = node.args.get("where")

                # No WHERE clause
                if not where:
                    stmt_type = "UPDATE" if isinstance(node, exp.Update) else "DELETE"
                    issues.append(
                        self.create_issue(
                            query=query,
                            message=f"{stmt_type} without WHERE clause — will lock entire table (lock escalation).",
                            snippet=str(node)[:100],
                        )
                    )
                else:
                    # Check for non-selective WHERE (e.g., status = 'active' might match millions)
                    query_upper = query.raw.upper()

                    # Heuristic: no indexed column patterns (id, _id suffix)
                    has_likely_pk = any(
                        term in query_upper
                        for term in [
                            "WHERE ID",
                            "WHERE USER_ID",
                            "WHERE ORDER_ID",
                            "_ID =",
                            "_ID IN",
                            "PRIMARY",
                        ]
                    )

                    has_limit = "TOP" in query_upper or "LIMIT" in query_upper

                    if not has_likely_pk and not has_limit:
                        stmt_type = (
                            "UPDATE" if isinstance(node, exp.Update) else "DELETE"
                        )
                        issues.append(
                            self.create_issue(
                                query=query,
                                message=f"{stmt_type} with non-selective WHERE may lock many rows — consider batching.",
                                snippet=str(node)[:100],
                            )
                        )
        return issues

    impact = (
        "SQL Server escalates row locks to table locks after ~5000 locks. Wide "
        "UPDATE/DELETE statements lock the entire table, blocking all other operations."
    )
    fix_guidance = (
        "Add selective WHERE with indexed columns. Use TOP/LIMIT for batching. "
        "Consider ROWLOCK hint if table lock is not acceptable. Process in smaller "
        "batches."
    )
