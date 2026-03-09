from __future__ import annotations

"""
Compliance Hipaa rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Issue, Query, Severity
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    'PHIAccessWithoutAuditRule',
    'PHIMinimumNecessaryRule',
    'UnencryptedPHITransitRule',
]


class PHIAccessWithoutAuditRule(ASTRule):
    """Detects SELECT queries on healthcare-related tables without corresponding audit logging pattern."""

    id = "COMP-HIPAA-001"
    name = "PHI Access Without Audit Trail"
    description = (
        "Detects SELECT queries on healthcare-related tables/columns without corresponding "
        "audit logging pattern, violating HIPAA audit requirements (45 CFR § 164.312(b))."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_HIPAA

    _phi_tables = {
        "patients", "patient", "medical_records", "diagnoses", "prescriptions",
        "treatments", "procedures", "lab_results", "radiology", "encounters",
        "visits", "admissions", "insurance_claims", "billing_records",
        "health_records", "clinical_data", "ehr", "emr"
    }

    _phi_columns = {
        "ssn", "social_security", "mrn", "medical_record_number",
        "diagnosis", "condition", "medication", "prescription",
        "treatment", "procedure", "lab_result", "test_result",
        "health_status", "patient_id", "member_id"
    }

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        is_phi_access = False

        # Check tables
        tables = self._get_tables(ast)
        if any(t.lower() in self._phi_tables for t in tables):
            is_phi_access = True

        # Check columns
        if not is_phi_access:
            columns = self._get_columns(ast)
            if any(c.lower() in self._phi_columns for c in columns):
                is_phi_access = True

        if is_phi_access:
            # Simple heuristic: Check if query contains 'AUDIT' or 'LOG' keyword in join or CTE
            # or if it's accompanied by another query in a batch.
            # Here we check for presence of audit-related words in the raw SQL
            if not re.search(r"\b(audit|access_log|phi_log|compliance_log)\b", query.raw, re.IGNORECASE):
                issues.append(
                    self.create_issue(
                        query=query,
                        message="PHI access detected without apparent audit logging reference.",
                        snippet=query.raw[:100],
                    )
                )

        return issues

    impact = (
        "Lack of audit trails for PHI access prevents detection of unauthorized access "
        "and violates HIPAA Technical Safeguards, potentially leading to OCR "
        "investigations and significant civil money penalties."
    )
    fix_guidance = (
        "Ensure all queries accessing PHI are wrapped in a stored procedure or application "
        "service that performs mandatory audit logging. Consider using database-level "
        "Audit features (e.g., SQL Server Audit, Oracle Audit Vault)."
    )


class PHIMinimumNecessaryRule(ASTRule):
    """Detects broad PHI access (SELECT *) which may violate HIPAA 'Minimum Necessary' standard."""

    id = "COMP-HIPAA-002"
    name = "PHI Minimum Necessary Violation"
    description = (
        "Detects SELECT * queries on PHI tables. HIPAA requires covered entities to make "
        "reasonable efforts to limit PHI to the minimum necessary to accomplish the intended "
        "purpose (45 CFR § 164.502(b))."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_HIPAA

    _phi_tables = PHIAccessWithoutAuditRule._phi_tables

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []

        # Check for SELECT * on PHI tables
        if query.query_type == "SELECT":
            # Check if any star expression exists
            stars = ast.find_all(exp.Star)
            if any(stars):
                tables = self._get_tables(ast)
                if any(t.lower() in self._phi_tables for t in tables):
                    issues.append(
                        self.create_issue(
                            query=query,
                            message="SELECT * used on PHI table — violates 'Minimum Necessary' standard.",
                            snippet="SELECT *",
                        )
                    )
        return issues

    impact = (
        "Fetching all columns from healthcare tables often retrieves unnecessary "
        "protected health information, increasing the risk and scope of a potential data breach."
    )
    fix_guidance = (
        "Explicitly list only the columns required for the specific business function. "
        "Avoid using SELECT * on tables containing PHI."
    )


class UnencryptedPHITransitRule(PatternRule):
    """Detects PHI-related queries over insecure protocols signal."""

    id = "COMP-HIPAA-003"
    name = "Unencrypted PHI Transit Signal"
    description = (
        "Detects connection strings or configuration queries hinting at unencrypted PHI transit "
        "(e.g., SSL/TLS disabled in connection properties for healthcare databases)."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_HIPAA

    pattern = (
        r"\b(encrypt=false|trustServerCertificate=true|sslmode=disable|ssl_mode=none)\b"
        r".*?\b(patients|medical_records|phi|health|ehr)\b"
    )
    message_template = "Insecure connection parameters detected for PHI-related database: {match}"

    impact = (
        "Transmitting PHI over unencrypted connections violates the HIPAA Security Rule "
        "regarding transmission security (45 CFR § 164.312(e)(1)) and exposes data to "
        "man-in-the-middle attacks."
    )
    fix_guidance = (
        "Enable SSL/TLS for all database connections. Update connection strings to use "
        "encrypt=true, sslmode=verify-full, or equivalent secure parameters."
    )
