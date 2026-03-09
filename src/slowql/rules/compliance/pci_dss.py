from __future__ import annotations

"""
Compliance Pci dss rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'CVVStorageRule',
    'CardholderDataRetentionRule',
    'PANExposureRule',
]


class PANExposureRule(PatternRule):
    """Detects Primary Account Number (PAN) exposure in queries."""

    id = "COMP-PCI-001"
    name = "PAN Exposure in SQL"
    description = (
        "Detects queries that select or store unmasked 16-digit credit card numbers (PAN). "
        "PCI-DSS Requirement 3.3 requires masking PAN when displayed."
    )
    severity = Severity.HIGH
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_PCI

    # Regex for 13-19 digit card numbers usually starting with specific digits
    pattern = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b"
    message_template = "Potential unmasked PAN (Credit Card Number) detected in query: {match}"

    impact = (
        "Unmasked PANs in logs, cache, or application output violate PCI-DSS and increase "
        "the risk of financial fraud and massive non-compliance fines."
    )
    fix_guidance = (
        "Mask PANs at the database level using Dynamic Data Masking or in the application "
        "layer. Only store the last 4 digits if full PAN is not required. Use tokenization "
        "services."
    )


class CVVStorageRule(PatternRule):
    """Detects storage of sensitive authentication data (CVV/CVC)."""

    id = "COMP-PCI-002"
    name = "CVV Storage Violation"
    description = (
        "Detects INSERT or CREATE TABLE statements referencing CVV, CVC, or CID. "
        "PCI-DSS Requirement 3.2 strictly prohibits storage of card security codes after "
        "authorization, even if encrypted."
    )
    severity = Severity.CRITICAL
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_PCI

    pattern = r"\b(INSERT|CREATE)\b.*?\b(cvv|cvc|cid|security_code|card_verification)\b"
    message_template = "Illegal storage of sensitive authentication data (CVV/CVC) detected: {match}"

    impact = (
        "Storing CVV/CVC is a major PCI-DSS violation. It makes the database a prime target "
        "for attackers, as stolen CVVs enable 'CNP' (Card Not Present) fraud."
    )
    fix_guidance = (
        "DELETE all columns and code that store CVV/CVC. These values must only be used "
        "during the real-time authorization process and never persisted to disk."
    )


class CardholderDataRetentionRule(PatternRule):
    """Detects missing retention policy signals for cardholder data."""

    id = "COMP-PCI-003"
    name = "Data Retention Violation"
    description = (
        "Detects queries on transaction/cardholder tables without date filters or "
        "purge logic, potentially violating PCI-DSS Requirement 3.1."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COMPLIANCE
    category = Category.COMP_PCI

    pattern = r"\bSELECT\b.*?\bFROM\b.*?\b(transactions|cardholder_data|payments)\b(?!.*?\bWHERE\b.*?\b(date|created_at|timestamp|retention)\b)"
    message_template = "Query on cardholder data without time-based filter — verify retention policy compliance: {match}"

    impact = (
        "Keeping cardholder data longer than necessary increases risk and violates "
        "PCI data minimization principles. It expands the scope of investigations in case of breach."
    )
    fix_guidance = (
        "Implement automated purge scripts or partitioning to remove data older than the "
        "defined retention period. Always include date filters when querying large "
        "transactional datasets."
    )
