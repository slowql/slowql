from __future__ import annotations

"""
Compliance General rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'AuditLogTamperingRule',
    'RetentionPolicyMissingRule',
    'UnencryptedSensitiveColumnRule',
]


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
