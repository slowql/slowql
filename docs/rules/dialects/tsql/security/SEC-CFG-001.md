# Dangerous Server Configuration (SEC-CFG-001)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Tsql)

## Description
Enabling xp_cmdshell gives SQL users full operating system command execution. Ole Automation and CLR allow arbitrary code execution within the database process. These are the most common post-exploitation steps in SQL Server attacks.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Keep dangerous features disabled. Use sp_configure to verify settings. If xp_cmdshell or CLR is required, restrict access to specific logins and audit all usage. Never enable these features in production without a documented security review.
