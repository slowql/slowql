# Missing Retention Policy Signal (COMP-RET-001)

**Dimension**: Compliance
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Indefinite retention of audit and log data violates GDPR storage limitation principles and increases breach exposure surface.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Implement a documented retention policy. Use partitioning with scheduled partition drops, or a scheduled DELETE WHERE created_at < NOW() - INTERVAL. Document the retention period in a data inventory.
