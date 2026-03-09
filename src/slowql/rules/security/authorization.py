from __future__ import annotations

"""
Security Authorization rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'HorizontalAuthorizationBypassRule',
    'PrivilegeEscalationRoleGrantRule',
    'SchemaOwnershipChangeRule',
]


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
