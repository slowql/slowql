"""
Compliance Sox rules.
"""

from __future__ import annotations

import re
from typing import Any

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'FinancialChangeTrackingRule',
    'SegregationOfDutiesRule',
]


class FinancialChangeTrackingRule(ASTRule):
    """Detects UPDATE/DELETE on financial tables without a linked change reason or ticket ID."""

    id = "COMP-SOX-001"
    name = "Financial Data Modification Without Change Tracking"
    description = (
        "Detects UPDATE or DELETE statements on financial tables (ledger, accounts, payments, "
        "salaries) without a comment or where clause containing a change reason or "
        "tracking ID (ticket, bug, ref), violating SOX internal control requirements."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_SOX

    _financial_tables = {
        "ledger", "accounts", "payments", "salaries", "payroll", "revenue",
        "expenses", "general_ledger", "trial_balance", "balance_sheet"
    }

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        if query.query_type in ("UPDATE", "DELETE"):
            tables = self._get_tables(ast)
            if any(t.lower() in self._financial_tables for t in tables):
                # Check for ticket/reason in query string (raw) as it's often in comments
                if not re.search(r"\b(ticket|req|reason|change_id|ref|bug|jira)\s*[:=]?\s*\w+\b", query.raw, re.IGNORECASE):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="Financial data modification without change tracking reference.",
                            snippet=query.raw[:100],
                        )
                    )
        return issues

    impact = (
        "Untracked modifications to financial records violate Sarbanes-Oxley (SOX) "
        "Section 404 internal controls, potentially leading to audit failures and "
        "legal liabilities for public companies."
    )
    fix_guidance = (
        "Always include a change tracking reference (e.g., Jira ticket ID or change reason) "
        "in the query comment or as a mandatory field in the audit metadata columns."
    )


class SegregationOfDutiesRule(PatternRule):
    """Detects queries that might indicate a Segregation of Duties (SoD) violation."""

    id = "COMP-SOX-002"
    name = "Segregation of Duties Violation"
    description = (
        "Detects queries where the same user context is performing both 'Creator' "
        "and 'Approver' functions on financial transactions, signaling an SoD risk."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_SOX

    pattern = (
        r"\bUPDATE\s+.*?\bSET\s+.*?\b(approved_by|status)\b.*?\bWHERE\b.*?\bcreated_by\b"
    )
    message_template = "Potential Segregation of Duties violation: User attempting to approve their own creation: {match}"

    impact = (
        "SoD violations allow a single individual to initiate and approve a financial "
        "transaction, creating a significant risk of fraud and material misstatement."
    )
    fix_guidance = (
        "Enforce SoD at the application and database trigger level. Ensure that "
        "created_by and approved_by values are never the same for the same record."
    )
