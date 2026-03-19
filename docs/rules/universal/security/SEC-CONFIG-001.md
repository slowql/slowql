# Hardcoded Database Credentials (SEC-CONFIG-001)

**Dimension**: Security
**Severity**: Critical
**Scope**: Universal (All Dialects)

## Description
Hardcoded credentials in queries are stored in query logs, execution history, source control, and backups. One leaked log file exposes database access permanently.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use connection pooling with credentials from secure vaults (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault). Never embed passwords in SQL. Use Windows/Kerberos authentication where possible.
