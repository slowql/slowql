from __future__ import annotations

"""
Security Information rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'DatabaseVersionDisclosureRule',
    'SchemaInformationDisclosureRule',
    'TimingAttackPatternRule',
    'VerboseErrorMessageDisclosureRule',
]


class DatabaseVersionDisclosureRule(PatternRule):
    """Detects queries that expose database version information."""

    id = "SEC-INFO-001"
    name = "Database Version Disclosure"
    description = (
        "Detects queries that expose database version information, which aids attackers in finding "
        "version-specific vulnerabilities."
    )
    severity = Severity.LOW
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE

    pattern = r'(?:@@VERSION|VERSION\(\)|SERVERPROPERTY\(\'ProductVersion\'\)|pg_version\(\)|BANNER|v\$version)'

    impact = (
        "Exposing database version helps attackers identify known vulnerabilities (CVEs) specific to that "
        "version. This information should not be accessible to application users."
    )
    fix_guidance = (
        "Never expose version info to end users. If needed for admin purposes, require authentication and "
        "log access. Return generic error messages without version details."
    )


class SchemaInformationDisclosureRule(PatternRule):
    """Detects queries accessing system catalog tables that expose schema information."""

    id = "SEC-INFO-002"
    name = "Schema Information Disclosure"
    description = (
        "Detects queries accessing system catalog tables that expose schema information to potential attackers."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE

    pattern = r'\b(INFORMATION_SCHEMA|sys\.|pg_catalog|ALL_TABLES|USER_TABLES|DBA_TABLES|SHOW\s+TABLES|SHOW\s+COLUMNS|DESCRIBE|syscolumns|sysobjects)\b'

    impact = (
        "Schema enumeration reveals table names, column names, and relationships. Attackers use this for "
        "targeted SQL injection and privilege escalation. Should be restricted to DBAs only."
    )
    fix_guidance = (
        "Restrict access to system catalogs using database permissions. Don't expose schema info through "
        "application errors. Use views to hide underlying schema from application."
    )


class TimingAttackPatternRule(PatternRule):
    """Detects password/authentication queries without constant-time comparison."""

    id = "SEC-INFO-003"
    name = "Timing Attack Pattern"
    description = (
        "Detects password/authentication queries without constant-time comparison, enabling timing attacks."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE

    pattern = r'\b(SLEEP|WAITFOR\s+DELAY|DBMS_LOCK\.SLEEP|PG_SLEEP)\b\s*\(\s*\d+\s*\)'

    impact = (
        "String comparison of passwords has variable timing based on match length. Attackers can infer "
        "password characters through timing analysis. Each character leak reduces brute-force complexity."
    )
    fix_guidance = (
        "Use constant-time comparison for password verification. Hash passwords and compare hashes. Add "
        "artificial delays to equalize timing. Use bcrypt/Argon2 which have built-in constant-time comparison."
    )


class VerboseErrorMessageDisclosureRule(PatternRule):
    """Detects error handling that may expose sensitive information."""

    id = "SEC-INFO-004"
    name = "Verbose Error Messages"
    description = (
        "Detects error handling that may expose sensitive information (stack traces, query text, schema details)."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE

    pattern = r'\b(RAISERROR|THROW|SIGNAL)\b[^;]*\b(@@ERROR|ERROR_MESSAGE|SQLERRM|SQLSTATE)|\bCAST\s*\(\s*(?:@@VERSION|VERSION\(\)|BANNER)'

    impact = (
        "Error messages containing schema names, query fragments, or stack traces help attackers "
        "understand database structure and find injection points. Production errors should be generic."
    )
    fix_guidance = (
        "Return generic error messages to users ('An error occurred. Contact support.'). Log detailed "
        "errors server-side only. Never expose query text, object names, or internal errors to clients."
    )
