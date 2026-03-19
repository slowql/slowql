# Distributed Transaction Overhead (COST-CROSS-003)

**Dimension**: Cost
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Distributed transactions require 2-phase commit across nodes, holding locks for network round-trips. Throughput drops significantly.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Avoid distributed transactions. Use Saga pattern for cross-service consistency. Implement compensating transactions or eventual consistency.
