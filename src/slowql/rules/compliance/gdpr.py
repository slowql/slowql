from __future__ import annotations

"""
Compliance Gdpr rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'ConsentTableMissingRule',
    'ConsentWithdrawalRule',
    'CrossBorderDataTransferRule',
    'DataExportCompletenessRule',
    'PIIExposureRule',
    'RightToErasureRule',
]


class PIIExposureRule(PatternRule):
    """Detects potential PII selection."""

    id = "COMP-GDPR-001"
    name = "Potential PII Selection"
    description = "Detects selection of common PII column names (email, ssn, password)."
    severity = Severity.MEDIUM
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_GDPR

    pattern = r"\b(email|ssn|social_security|credit_card|cc_num|passport)\b"
    message_template = "Potential PII column accessed: {match}"
    impact = "Accessing PII requires audit logging and strict access controls under GDPR/CCPA."


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


class DataExportCompletenessRule(ASTRule):
    """Detects potential gaps in data subject access request (DSAR) export queries."""

    id = "COMP-GDPR-005"
    name = "Data Subject Request Without Completeness Check"
    description = (
        "Detects SELECT queries for user data export (GDPR Art. 15) that use broad "
        "filters but might miss related sensitive tables like logs or backups."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_GDPR

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        # Look for export-like queries
        if query.query_type == "SELECT" and re.search(r"\b(export|dsar|access_request|subject_data)\b", query.raw, re.IGNORECASE):
            tables = self._get_tables(ast)
            # If exporting from 'users' but not joining 'activity_logs' or similar
            if any(t.lower() == "users" for t in tables):
                if not any(t.lower() in ("activity_logs", "user_logs", "audit_log", "metadata") for t in tables):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="User data export might be missing related audit or activity logs.",
                            snippet=query.raw[:100],
                        )
                    )
        return issues

    impact = (
        "Incomplete responses to Data Subject Access Requests (DSAR) violate GDPR "
        "Article 15, leading to regulatory complaints and potential fines from Data "
        "Protection Authorities."
    )
    fix_guidance = (
        "Verify that all sources of personal data, including logs, secondary profiles, "
        "and metadata, are included in the export query or process."
    )


class ConsentWithdrawalRule(ASTRule):
    """Detects queries accessing data where consent withdrawal signals are ignored."""

    id = "COMP-GDPR-006"
    name = "Consent Withdrawal Not Honored"
    description = (
        "Detects SELECT queries on personal data that do not filter for active "
        "consent (e.g., missing WHERE consent_withdrawn = 0)."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_GDPR

    _pii_tables = {"users", "profiles", "customers", "contacts", "leads"}

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        if query.query_type == "SELECT":
            tables = self._get_tables(ast)
            if any(t.lower() in self._pii_tables for t in tables):
                where_cols = self._get_where_columns(ast)
                if not any(c in ("consent", "consent_status", "opt_in", "active") for c in where_cols):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="PII access without active consent filter.",
                            snippet=query.raw[:100],
                        )
                    )
        return issues

    impact = (
        "Failing to honor consent withdrawal violates GDPR Article 7. Continuing to process "
        "data after consent is revoked is a major non-compliance event."
    )
    fix_guidance = (
        "Always include a consent check in the WHERE clause when querying personal data "
        "for processing categories that require consent."
    )
