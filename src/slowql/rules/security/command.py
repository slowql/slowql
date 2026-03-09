from __future__ import annotations

"""
Security Command rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'LocalFileInclusionRule',
    'OSCommandInjectionRule',
    'PathTraversalRule',
    'SSRFViaDatabaseRule',
]


class OSCommandInjectionRule(PatternRule):
    """Detects use of system command execution procedures."""

    id = "SEC-CMD-001"
    name = "OS Command Injection"
    description = (
        "Detects use of system command execution procedures (xp_cmdshell, SHELL, etc.) "
        "which can lead to OS-level compromise."
    )
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r'\b(xp_cmdshell|sp_OACreate|sp_OAMethod|SHELL|EXEC\s+master\.\.xp_cmdshell|pg_read_file|pg_execute_server_program)\b'

    impact = (
        "OS command execution from SQL gives attackers full server access. xp_cmdshell with user input "
        "= remote code execution. Attacker can install malware, exfiltrate data, pivot to other systems."
    )
    fix_guidance = (
        "NEVER use xp_cmdshell. Disable it: sp_configure 'xp_cmdshell', 0. Move system operations to "
        "application layer with proper input validation. If absolutely required, use whitelisted "
        "commands only and strict validation."
    )


class PathTraversalRule(PatternRule):
    """Detects file operations with user input that could enable directory traversal."""

    id = "SEC-PATH-001"
    name = "Path Traversal in File Operations"
    description = (
        "Detects file operations with user input that could enable directory traversal attacks (../, ..)."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_ACCESS

    pattern = r'\b(OPENROWSET|BULK\s+INSERT|LOAD_FILE|INTO\s+OUTFILE|UTL_FILE|BFILE|DBMS_LOB\.LOADFROMFILE)\b[^;]*(\+|CONCAT|\|\|)[^;]*[\'"][^\'"]*\.\.[/\\]'

    impact = (
        "Path traversal allows attackers to read/write arbitrary files on the server. Reading /etc/passwd "
        "or C:\\Windows\\System32\\config\\SAM exposes credentials. Writing enables code execution."
    )
    fix_guidance = (
        "Validate file paths against whitelist. Use absolute paths only. Reject paths containing ../ or ..\\. "
        "Sandbox file operations to specific directory. Use path canonicalization and verify result."
    )


class LocalFileInclusionRule(PatternRule):
    """Detects dynamic loading of SQL files or stored procedures."""

    id = "SEC-PATH-002"
    name = "Local File Inclusion"
    description = (
        "Detects dynamic loading of SQL files or stored procedures that could enable arbitrary code execution."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r'\b(EXECUTE|EXEC|SOURCE|\\i|@)\b[^;]*(\+|CONCAT|\|\|)[^;]*\.sql\b'

    impact = (
        "Including SQL files based on user input allows attackers to execute arbitrary SQL code. "
        "If attacker can upload a .sql file, they can execute it via file inclusion."
    )
    fix_guidance = (
        "Never include SQL files based on user input. Use whitelist of allowed procedures. Validate against "
        "allowed set of script names. Store procedures in database, not files."
    )


class SSRFViaDatabaseRule(PatternRule):
    """Detects database functions that make HTTP requests."""

    id = "SEC-SSRF-001"
    name = "Server-Side Request Forgery via Database"
    description = (
        "Detects database functions that make HTTP requests, which can be abused for SSRF attacks."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r'\b(sp_OACreate.*XMLHTTP|UTL_HTTP|DBMS_NETWORK|HTTPURLConnection|CURL)\b|\bOPENROWSET\b.*[\'"][^\'"]*(?:http|https|ftp|ldap|\\\\)'

    impact = (
        "SSRF via database allows attackers to scan internal networks, access cloud metadata services "
        "(AWS EC2 metadata at 169.254.169.254), bypass firewalls, and exfiltrate data."
    )
    fix_guidance = (
        "Disable HTTP functions in database. If needed, use allowlist of approved URLs. Block access to "
        "private IP ranges (10.0.0.0/8, 169.254.0.0/16). Validate and sanitize all URLs."
    )
