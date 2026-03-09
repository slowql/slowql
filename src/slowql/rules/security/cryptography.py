from __future__ import annotations

"""
Security Cryptography rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'HardcodedEncryptionKeyRule',
    'PlaintextPasswordInQueryRule',
    'WeakEncryptionAlgorithmRule',
    'WeakHashingAlgorithmRule',
]


class WeakHashingAlgorithmRule(PatternRule):
    """Detects use of cryptographically broken hashing algorithms (MD5, SHA1)."""

    id = "SEC-CRYPTO-001"
    name = "Weak Hashing Algorithm"
    description = (
        "Detects use of cryptographically broken hashing algorithms (MD5, SHA1) for password "
        "or sensitive data hashing."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_CRYPTO

    pattern = r"\b(MD5|SHA1|SHA)\s*\(\s*[^)]*\b(password|passwd|pwd|secret|token|key|credential)\b"
    message_template = "Weak hashing algorithm detected: {match}"

    impact = (
        "MD5 and SHA1 are cryptographically broken. GPU clusters can crack MD5 hashes at 200+ billion "
        "attempts/second. Rainbow tables provide instant lookups for common passwords."
    )
    fix_guidance = (
        "Use bcrypt, scrypt, or Argon2id for passwords (with appropriate cost factors). For data integrity "
        "checksums, use SHA-256 or SHA-3. Never use MD5/SHA1 for security purposes."
    )


class PlaintextPasswordInQueryRule(PatternRule):
    """Detects INSERT/UPDATE statements that appear to store plaintext passwords."""

    id = "SEC-CRYPTO-002"
    name = "Plaintext Password in Query"
    description = (
        "Detects INSERT/UPDATE statements that appear to store plaintext passwords (string literals assigned "
        "to password columns without hashing function)."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_CRYPTO

    pattern = r"\b(INSERT\s+INTO|UPDATE)\b[^;]*\b(password|passwd|pwd|secret_key|api_key|auth_token)\b[^;]*?(?:=\s*|VALUES\s*\()[^;(]*?['\"][^'\"()]{4,}['\"]"
    message_template = "Potential plaintext password detected in query: {match}"

    impact = (
        "Plaintext passwords in databases are catastrophic during breaches. A single leaked backup exposes "
        "all credentials. Violates every security compliance framework."
    )
    fix_guidance = (
        "Hash passwords at the application layer using bcrypt/Argon2id BEFORE SQL insertion. Never pass "
        "plaintext passwords through SQL. Store only the hash."
    )


class HardcodedEncryptionKeyRule(PatternRule):
    """Detects encryption/decryption functions with hardcoded key values."""

    id = "SEC-CRYPTO-003"
    name = "Hardcoded Encryption Key"
    description = "Detects encryption/decryption functions with hardcoded key values instead of key references."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_CRYPTO

    pattern = r"\b(AES_ENCRYPT|AES_DECRYPT|ENCRYPT|DECRYPT|ENCRYPTBYKEY|DECRYPTBYKEY|HASHBYTES|HMAC)\s*\([^)]*,\s*['\"][A-Za-z0-9\+/=!@#\$%^&\*\-]{8,}['\"]"
    message_template = "Hardcoded encryption key detected: {match}"

    impact = (
        "Hardcoded keys in queries appear in query logs, execution plans, source control history, and "
        "monitoring tools. Key compromise means total data compromise with no rotation path."
    )
    fix_guidance = (
        "Use HSM or dedicated key management (AWS KMS, Azure Key Vault, HashiCorp Vault). "
        "Reference keys by name/alias, never by value. Implement key rotation procedures."
    )


class WeakEncryptionAlgorithmRule(PatternRule):
    """Detects use of deprecated or weak encryption algorithms."""

    id = "SEC-CRYPTO-004"
    name = "Weak Encryption Algorithm"
    description = "Detects use of deprecated or weak encryption algorithms (DES, 3DES, RC4, Blowfish with small keys)."
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_CRYPTO

    pattern = r"\b(DES_ENCRYPT|DES_DECRYPT|TRIPLE_DES|3DES|RC4|RC2|BLOWFISH|IDEA)\s*\("
    message_template = "Weak encryption algorithm detected: {match}"

    impact = (
        "DES uses 56-bit keys, crackable in hours. RC4 has critical biases. These algorithms are prohibited "
        "by PCI-DSS, HIPAA, and most compliance frameworks."
    )
    fix_guidance = "Use AES-256-GCM for symmetric encryption. Migrate existing encrypted data to modern algorithms. Document encryption standards in security policy."
