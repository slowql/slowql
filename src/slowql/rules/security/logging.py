from __future__ import annotations

"""
Security Logging rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'AuditTrailManipulationRule',
    'SensitiveDataInErrorOutputRule',
]


class SensitiveDataInErrorOutputRule(PatternRule):
    """Detects error handling statements that may expose sensitive column values."""

    id = "SEC-LOG-001"
    name = "Sensitive Data in Error Output"
    description = "Detects error handling statements (RAISERROR, THROW, PRINT) that may expose sensitive column values."
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_LOGGING

    pattern = r"\b(RAISERROR|THROW|RAISE|PRINT|DBMS_OUTPUT\.PUT_LINE|RAISE\s+NOTICE)\b[^;]*\b(password|pwd|ssn|social_security|credit_card|card_number|cvv|secret|token|api_key|private_key)\b"
    message_template = "Sensitive data exposed in error output: {match}"

    impact = (
        "Sensitive data in error messages may be logged, displayed to users, or sent to monitoring systems. "
        "Error logs often have weaker access controls than databases."
    )
    fix_guidance = "Use generic error messages for user-facing output. Log sensitive context only to secure audit logs with strict access controls. Mask sensitive values in all output."


class AuditTrailManipulationRule(PatternRule):
    """Detects attempts to modify, delete, or disable audit logs and trails."""

    id = "SEC-LOG-002"
    name = "Audit Trail Manipulation"
    description = "Detects attempts to modify, delete, or disable audit logs and trails."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_LOGGING

    pattern = r"\b(DELETE\s+FROM|TRUNCATE|UPDATE|DROP\s+TABLE)\s+[^;]*\b(audit|audit_log|audit_trail|event_log|security_log|access_log|change_log|history)\b|\b(SET\s+(?:sql_log_off|general_log|audit_trail|log_statement)\s*=\s*(?:0|OFF|NONE|false))\b"
    message_template = "Audit trail manipulation detected: {match}"

    impact = (
        "Audit log tampering destroys forensic capability and violates every compliance framework. "
        "Attackers delete logs to cover tracks. This is often evidence of active compromise."
    )
    fix_guidance = "Make audit tables append-only (no UPDATE/DELETE permissions). Use separate audit database with restricted access. Implement real-time log shipping to immutable storage."
