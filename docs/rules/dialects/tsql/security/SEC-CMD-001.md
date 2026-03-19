# OS Command Injection (SQL Server) (SEC-CMD-001)

**Dimension**: Security
**Severity**: Critical
**Scope**: Dialect Specific (Tsql)

## Description
OS command execution from SQL gives attackers full server access. xp_cmdshell with user input = remote code execution. Attacker can install malware, exfiltrate data, pivot to other systems.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
NEVER use xp_cmdshell. Disable it: sp_configure 'xp_cmdshell', 0. Move system operations to application layer with proper input validation. If absolutely required, use whitelisted commands only and strict validation.
