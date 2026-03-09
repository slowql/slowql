from __future__ import annotations

"""
Security Data protection rules.
"""



from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    'DataExfiltrationViaFileRule',
    'RemoteDataAccessRule',
]


class DataExfiltrationViaFileRule(PatternRule):
    """Detects SQL file operations that can export or read data."""

    id = "SEC-DATA-001"
    name = "Data Exfiltration via File Operations"
    description = (
        "Detects SQL file operations that can export data to the filesystem or read "
        "arbitrary files: INTO OUTFILE, INTO DUMPFILE, LOAD_FILE(), LOAD DATA INFILE, "
        "BULK INSERT, and COPY FROM/TO PROGRAM. These are primary vectors for data "
        "exfiltration and arbitrary file read."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE

    pattern = (
        r"\bINTO\s+OUTFILE\b"
        r"|\bINTO\s+DUMPFILE\b"
        r"|\bLOAD_FILE\s*\("
        r"|\bLOAD\s+DATA\s+INFILE\b"
        r"|\bBULK\s+INSERT\b"
        r"|\bCOPY\b.+\bFROM\s+PROGRAM\b"
        r"|\bCOPY\b.+\bTO\s+PROGRAM\b"
    )
    message_template = "Data exfiltration via file operation detected: {match}"

    impact = (
        "Attackers can export entire tables to attacker-readable locations, read "
        "sensitive OS files (e.g., /etc/passwd, configuration files), or execute "
        "arbitrary OS commands via COPY PROGRAM."
    )
    fix_guidance = (
        "Restrict FILE privilege in MySQL. Disable LOAD DATA INFILE via "
        "local_infile=0. Revoke COPY permissions in PostgreSQL. Use application-level "
        "export mechanisms with proper access controls instead of SQL-level file operations."
    )


class RemoteDataAccessRule(PatternRule):
    """Detects remote/linked data access functions."""

    id = "SEC-DATA-002"
    name = "Remote/Linked Data Access"
    description = (
        "Detects remote data access functions that can connect to external servers: "
        "OPENROWSET, OPENDATASOURCE, OPENQUERY (SQL Server), and dblink functions "
        "(PostgreSQL). These can be exploited for data exfiltration and lateral "
        "movement to other database servers."
    )
    severity = Severity.HIGH
    dimension = Dimension.SECURITY
    category = Category.SEC_DATA_EXPOSURE

    pattern = (
        r"\bOPENROWSET\s*\("
        r"|\bOPENDATASOURCE\s*\("
        r"|\bOPENQUERY\s*\("
        r"|\bdblink_connect\s*\("
        r"|\bdblink_exec\s*\("
        r"|\bdblink\s*\("
    )
    message_template = "Remote data access detected: {match}"

    impact = (
        "Attackers can use remote access functions to exfiltrate data to external "
        "servers, pivot to other databases in the network, or connect to "
        "attacker-controlled servers to stage further attacks."
    )
    fix_guidance = (
        "Disable Ad Hoc Distributed Queries in SQL Server. Remove linked server "
        "connections that are not required. Restrict dblink extension usage in "
        "PostgreSQL. Use application-level integration instead of database-to-database "
        "direct connections."
    )
