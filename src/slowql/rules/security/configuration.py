"""
Security Configuration rules.
"""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "DangerousServerConfigRule",
    "DefaultCredentialUsageRule",
    "HardcodedCredentialsRule",
    "OverlyPermissiveAccessRule",
    "OverprivilegedExecutionContextRule",
    "WeakSSLConfigRule",
]


class DangerousServerConfigRule(PatternRule):
    """Detects sp_configure enabling dangerous SQL Server features."""

    id = "SEC-CFG-001"
    name = "Dangerous Server Configuration"
    description = (
        "Detects sp_configure commands that enable dangerous SQL Server features: "
        "xp_cmdshell (OS command execution), Ole Automation Procedures (COM object "
        "access), CLR integration (arbitrary .NET code execution), and Ad Hoc "
        "Distributed Queries (remote data access)."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_ACCESS
    dialects = ("tsql",)

    pattern = (
        r"\bsp_configure\b.+\bxp_cmdshell\b"
        r"|\bsp_configure\b.+\bOle\s+Automation\b"
        r"|\bsp_configure\b.+\bclr\s+enabled\b"
        r"|\bsp_configure\b.+\bAd\s+Hoc\s+Distributed\s+Queries\b"
    )
    message_template = "Dangerous server configuration detected: {match}"

    impact = (
        "Enabling xp_cmdshell gives SQL users full operating system command execution. "
        "Ole Automation and CLR allow arbitrary code execution within the database "
        "process. These are the most common post-exploitation steps in SQL Server attacks."
    )
    fix_guidance = (
        "Keep dangerous features disabled. Use sp_configure to verify settings. If "
        "xp_cmdshell or CLR is required, restrict access to specific logins and audit "
        "all usage. Never enable these features in production without a documented "
        "security review."
    )


class OverprivilegedExecutionContextRule(PatternRule):
    """Detects stored procedures with elevated execution contexts."""

    id = "SEC-PRIV-001"
    name = "Overprivileged Execution Context"
    description = (
        "Detects stored procedures, functions, or grants that use elevated execution "
        "contexts: EXECUTE AS dbo/sa/sysadmin, EXECUTE AS OWNER/SELF, SECURITY "
        "DEFINER (MySQL/PostgreSQL), WITH ADMIN OPTION, and WITH GRANT OPTION. "
        "These create privilege escalation paths."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = (
        r"\bEXECUTE\s+AS\s+(USER\s*=\s*)?'(dbo|sa|sysadmin)'"
        r"|\bEXECUTE\s+AS\s+LOGIN\s*=\s*'(sa|sysadmin)'"
        r"|\bEXECUTE\s+AS\s+(OWNER|SELF)\b"
        r"|\bSECURITY\s+DEFINER\b"
        r"|\bWITH\s+ADMIN\s+OPTION\b"
        r"|\bWITH\s+GRANT\s+OPTION\b"
    )
    message_template = "Overprivileged execution context detected: {match}"

    impact = (
        "Stored procedures running as high-privilege accounts can be exploited for "
        "privilege escalation. WITH ADMIN/GRANT OPTION creates uncontrolled permission "
        "propagation where any granted user can re-grant to others."
    )
    fix_guidance = (
        "Use EXECUTE AS CALLER or SECURITY INVOKER instead of DEFINER/OWNER. Avoid "
        "WITH ADMIN OPTION and WITH GRANT OPTION unless absolutely necessary. Run "
        "stored procedures with the minimum privileges required. Audit all objects "
        "running as dbo or sa."
    )


class HardcodedCredentialsRule(PatternRule):
    """Detects connection strings or CREATE USER statements with hardcoded passwords."""

    id = "SEC-CONFIG-001"
    name = "Hardcoded Database Credentials"
    description = (
        "Detects connection strings or CREATE USER statements with hardcoded passwords in queries."
    )
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r'(PASSWORD\s*=\s*[\'"][^\'"]{4,}[\'"]|pwd\s*=\s*[\'"][^\'"]{4,}[\'"]|IDENTIFIED\s+BY\s+[\'"][^\'"]+[\'"])'

    impact = (
        "Hardcoded credentials in queries are stored in query logs, execution history, source control, "
        "and backups. One leaked log file exposes database access permanently."
    )
    fix_guidance = (
        "Use connection pooling with credentials from secure vaults (Azure Key Vault, AWS Secrets Manager, "
        "HashiCorp Vault). Never embed passwords in SQL. Use Windows/Kerberos authentication where possible."
    )


class WeakSSLConfigRule(PatternRule):
    """Detects connection settings that disable encryption or use weak protocols."""

    id = "SEC-CONFIG-002"
    name = "Weak SSL/TLS Configuration"
    description = "Detects connection settings that disable encryption or use weak protocols."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r"(Encrypt\s*=\s*(false|no|0)|TrustServerCertificate\s*=\s*true|sslmode\s*=\s*(disable|allow|prefer)|ssl\s*=\s*(false|0))"

    impact = (
        "Disabling SSL/TLS exposes all data in transit to interception. Man-in-the-middle attacks can "
        "capture credentials, session tokens, and sensitive data. Required by PCI-DSS, HIPAA."
    )
    fix_guidance = (
        "Always use encrypted connections: Encrypt=True, sslmode=require. Use certificate validation: "
        "TrustServerCertificate=False. Enforce TLS 1.2+ minimum version."
    )


class DefaultCredentialUsageRule(PatternRule):
    """Detects use of default usernames/passwords."""

    id = "SEC-CONFIG-003"
    name = "Default Credential Usage"
    description = (
        "Detects use of default usernames/passwords (sa, admin, root with common passwords)."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r'\b(sa|admin|root|postgres|mysql)\b.*\b(Password\s*=\s*[\'"]?(sa|admin|root|password|123456|default)[\'"]?|IDENTIFIED\s+BY\s+[\'"]?(sa|admin|root|password)[\'"]?)'

    impact = (
        "Default credentials are the #1 cause of database breaches. Attackers scan for default sa password. "
        "Automated bots check common defaults within minutes of database exposure."
    )
    fix_guidance = (
        "Change all default passwords immediately. Disable default accounts. Use strong, unique passwords "
        "(20+ chars, random). Implement password rotation. Monitor for default credential usage attempts."
    )


class OverlyPermissiveAccessRule(PatternRule):
    """Detects database settings allowing connections from any host."""

    id = "SEC-CONFIG-004"
    name = "Overly Permissive CORS/Access"
    description = (
        "Detects database settings allowing connections from any host or overly broad IP ranges."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.SECURITY
    category = Category.SEC_AUTHENTICATION

    pattern = r'(GRANT\s+.*\s+TO\s+.*@[\'"]%[\'"]|CREATE\s+USER\s+.*@[\'"]%[\'"]|Host\s*=\s*[\'"]?(\*|0\.0\.0\.0|%|::|all)[\'"]?)'

    impact = (
        "Allowing connections from any host (@'%', Host=*) exposes database to internet-wide attacks. "
        "Attackers can brute-force credentials from anywhere. Should be limited to application server IPs only."
    )
    fix_guidance = (
        "Restrict access to specific IP addresses: @'10.0.1.5'. Use firewall rules. Implement VPC/private "
        "networking. For cloud databases, use private endpoints only."
    )
