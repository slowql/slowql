# Data Retention Violation (COMP-PCI-003)

**Dimension**: Compliance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Keeping cardholder data longer than necessary increases risk and violates PCI data minimization principles. It expands the scope of investigations in case of breach.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Implement automated purge scripts or partitioning to remove data older than the defined retention period. Always include date filters when querying large transactional datasets.
