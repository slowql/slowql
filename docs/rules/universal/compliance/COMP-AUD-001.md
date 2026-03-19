# Audit Log Tampering Risk (COMP-AUD-001)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Modifying audit logs violates regulatory non-repudiation requirements and may constitute evidence tampering. PCI-DSS 10.5 explicitly requires audit logs to be protected from modification.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Audit tables should be append-only. Use INSERT-only permissions on log tables. Implement write-once storage for compliance archives. Use database roles to prevent UPDATE/DELETE on audit tables.
