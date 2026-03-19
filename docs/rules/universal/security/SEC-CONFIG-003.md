# Default Credential Usage (SEC-CONFIG-003)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Default credentials are the #1 cause of database breaches. Attackers scan for default sa password. Automated bots check common defaults within minutes of database exposure.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Change all default passwords immediately. Disable default accounts. Use strong, unique passwords (20+ chars, random). Implement password rotation. Monitor for default credential usage attempts.
