# Oracle UTL Package Access (SEC-ORA-001)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Oracle)

## Description
UTL_HTTP enables server-side request forgery (SSRF) from the database. UTL_FILE enables reading and writing files on the database server. Both can be used for data exfiltration and lateral movement.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Restrict UTL package access using REVOKE EXECUTE. Use fine-grained access control lists (ACLs) via DBMS_NETWORK_ACL_ADMIN to limit network destinations. Audit all UTL usage.
