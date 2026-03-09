from __future__ import annotations

"""
Security Session rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'InsecureSessionTokenStorageRule',
    'SessionTimeoutNotEnforcedRule',
]


class InsecureSessionTokenStorageRule(PatternRule):
    """Detects storage or retrieval of session tokens without apparent hashing."""

    id = "SEC-SESSION-001"
    name = "Insecure Session Token Storage"
    description = "Detects storage or retrieval of session tokens without apparent hashing, enabling session hijacking if database is compromised."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_SESSION

    pattern = r"\b(INSERT\s+INTO|UPDATE)\b[^;]*\b(session_token|auth_token|access_token|refresh_token|bearer_token|jwt_token)\b[^;]*?(?:=\s*|VALUES\s*\()[^;(]*?['\"]?[A-Za-z0-9_\-\.]{20,}['\"]?"
    message_template = "Insecure session token storage detected: {match}"

    impact = (
        "Unhashed session tokens in databases can be stolen and replayed. Database dumps, SQL injection, "
        "or backup exposure immediately compromises all active sessions."
    )
    fix_guidance = "Store only hashed tokens (SHA-256 is sufficient for tokens with high entropy). Compare using hash, not plaintext. Implement short token TTLs and secure rotation."


class SessionTimeoutNotEnforcedRule(PatternRule):
    """Detects session validation queries that don't check expiration timestamps."""

    id = "SEC-SESSION-002"
    name = "Session Timeout Not Enforced"
    description = "Detects session validation queries that don't check expiration timestamps."
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_SESSION

    pattern = r"\bSELECT\b[^;]*\bFROM\s+\w*(session|token)[s]?\b[^;]*\bWHERE\b(?!.*\b(expir|valid_until|expires_at|ttl|created_at)\b)"
    message_template = "Session timeout validation missing in query: {match}"

    impact = (
        "Sessions without expiration validation remain valid indefinitely. Stolen tokens provide permanent access. "
        "Violates security best practices and compliance requirements."
    )
    fix_guidance = "Always validate token expiration: WHERE token = ? AND expires_at > NOW(). Implement absolute timeouts (24h) and idle timeouts (30min). Force re-authentication for sensitive operations."
