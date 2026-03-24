# Overly Permissive CORS/Access (SEC-CONFIG-004)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Allowing connections from any host (@'%', Host=*) exposes database to internet-wide attacks. Attackers can brute-force credentials from anywhere. Should be limited to application server IPs only.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
