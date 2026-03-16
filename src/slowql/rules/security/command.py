"""
Security Command rules.
"""

from __future__ import annotations

from typing import ClassVar

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "ClickHouseUrlFunctionRule",
    "ClickHouseUrlFunctionRule",
    "LocalFileInclusionRule",
    "OSCommandInjectionPostgresRule",
    "OSCommandInjectionTsqlRule",
    "OpenRowsetRule",
    "OracleUtlAccessRule",
    "PathTraversalRule",
    "SSRFViaDatabaseRule",
    "SpOACreateRule",
]


class OSCommandInjectionTsqlRule(PatternRule):
    """Detects use of system command execution procedures in SQL Server."""

    id = "SEC-CMD-001"
    name = "OS Command Injection (SQL Server)"
    description = (
        "Detects use of system command execution procedures (xp_cmdshell, etc.) "
        "which can lead to OS-level compromise."
    )
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION
    dialects: ClassVar[tuple[str, ...]] = ("tsql",)

    pattern = r"\b(xp_cmdshell|sp_OACreate|sp_OAMethod|EXEC\s+master\.\.xp_cmdshell)\b"

    impact = (
        "OS command execution from SQL gives attackers full server access. xp_cmdshell with user input "
        "= remote code execution. Attacker can install malware, exfiltrate data, pivot to other systems."
    )
    fix_guidance = (
        "NEVER use xp_cmdshell. Disable it: sp_configure 'xp_cmdshell', 0. Move system operations to "
        "application layer with proper input validation. If absolutely required, use whitelisted "
        "commands only and strict validation."
    )


class OSCommandInjectionPostgresRule(PatternRule):
    """Detects use of system command execution procedures in PostgreSQL."""

    id = "SEC-CMD-001-PG"
    name = "OS Command Injection (PostgreSQL)"
    description = (
        "Detects use of system command execution procedures which can lead to OS-level compromise."
    )
    dialects: ClassVar[tuple[str, ...]] = ("postgresql",)
    pattern = r"\b(pg_read_file|pg_execute_server_program|pg_ls_dir|pg_read_binary_file|FROM\s+PROGRAM|libc\.so)\b"
    message_template = "PostgreSQL OS command function detected: {match}"
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION
    impact = (
        "pg_read_file and pg_execute_server_program allow reading arbitrary files "
        "and executing OS commands. Requires superuser — indicates privilege abuse."
    )
    fix_guidance = (
        "Revoke superuser from application accounts. Never call pg_execute_server_program "
        "from application SQL. Use application-layer file operations instead."
    )


class PathTraversalRule(PatternRule):
    """Detects file operations with user input that could enable directory traversal."""

    id = "SEC-PATH-001"
    name = "Path Traversal in File Operations"
    description = "Detects file operations with user input that could enable directory traversal attacks (../, ..)."
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
    description = "Detects dynamic loading of SQL files or stored procedures that could enable arbitrary code execution."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_INJECTION

    pattern = r"\b(EXECUTE|EXEC|SOURCE|\\i|@)\b[^;]*(\+|CONCAT|\|\|)[^;]*\.sql\b"

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


class OracleUtlAccessRule(PatternRule):
    """Detects Oracle UTL_HTTP/UTL_FILE/UTL_SMTP package access."""

    id = "SEC-ORA-001"
    name = "Oracle UTL Package Access"
    description = (
        "Detects usage of Oracle UTL packages (UTL_HTTP, UTL_FILE, UTL_SMTP, "
        "UTL_TCP, UTL_INADDR) which provide network and file system access "
        "from within the database. These are common vectors for SSRF, data "
        "exfiltration, and lateral movement."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE
    dialects = ("oracle",)

    pattern = r"\bUTL_(?:HTTP|FILE|SMTP|TCP|INADDR)\b"
    message_template = "Oracle UTL package access detected — potential SSRF or data exfiltration: {match}"

    impact = (
        "UTL_HTTP enables server-side request forgery (SSRF) from the database. "
        "UTL_FILE enables reading and writing files on the database server. "
        "Both can be used for data exfiltration and lateral movement."
    )
    fix_guidance = (
        "Restrict UTL package access using REVOKE EXECUTE. Use fine-grained "
        "access control lists (ACLs) via DBMS_NETWORK_ACL_ADMIN to limit "
        "network destinations. Audit all UTL usage."
    )


class OpenRowsetRule(PatternRule):
    """Detects OPENROWSET/OPENDATASOURCE usage in T-SQL."""

    id = "SEC-TSQL-001"
    name = "OPENROWSET / OPENDATASOURCE Usage"
    description = "OPENROWSET and OPENDATASOURCE allow ad-hoc remote data access — SSRF risk."
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE
    dialects = ("tsql",)
    pattern = r"\b(?:OPENROWSET|OPENDATASOURCE)\s*\("
    message_template = "Ad-hoc remote data access detected: {match}"
    impact = "OPENROWSET can read from arbitrary OLE DB sources including file system."
    fix_guidance = "Disable Ad Hoc Distributed Queries. Use linked servers with restricted permissions."


class SpOACreateRule(PatternRule):
    """Detects sp_OACreate OLE Automation usage in T-SQL."""

    id = "SEC-TSQL-002"
    name = "OLE Automation (sp_OACreate)"
    description = "sp_OACreate allows creating COM objects from T-SQL — arbitrary code execution risk."
    severity = Severity.CRITICAL
    dimension = Dimension.SECURITY
    category = Category.SEC_ACCESS
    dialects = ("tsql",)
    pattern = r"\bsp_OA(?:Create|Method|GetProperty|SetProperty|Destroy)\b"
    message_template = "OLE Automation procedure detected: {match}"
    impact = "OLE Automation enables arbitrary COM object instantiation and host compromise."
    fix_guidance = "Disable OLE Automation: sp_configure 'Ole Automation Procedures', 0."


class ClickHouseUrlFunctionRule(PatternRule):
    """Detects url() table function in ClickHouse (SSRF risk)."""

    id = "SEC-CH-001"
    name = "ClickHouse url() Table Function"
    description = (
        "ClickHouse's url() table function fetches data from arbitrary "
        "HTTP endpoints. If the URL is user-controlled, this enables "
        "Server-Side Request Forgery (SSRF)."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE
    dialects = ("clickhouse",)

    pattern = r"\burl\s*\(\s*['\"]https?://"
    message_template = "ClickHouse url() table function — SSRF risk: {match}"

    impact = (
        "url() can reach internal services, cloud metadata endpoints "
        "(169.254.169.254), and exfiltrate data via HTTP requests."
    )
    fix_guidance = (
        "Restrict url() with allowed_hosts in config.xml. Use named "
        "collections for approved external sources. Audit all url() usage."
    )
