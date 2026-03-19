# Overly Permissive CORS/Access (SEC-CONFIG-004)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Allowing connections from any host (@'%', Host=*) exposes database to internet-wide attacks. Attackers can brute-force credentials from anywhere. Should be limited to application server IPs only.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Restrict access to specific IP addresses: @'10.0.1.5'. Use firewall rules. Implement VPC/private networking. For cloud databases, use private endpoints only.
