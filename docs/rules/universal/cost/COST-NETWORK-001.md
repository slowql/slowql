# Cross-Region Data Transfer (COST-NETWORK-001)

**Dimension**: Cost
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Cross-region queries incur data egress charges (e.g., $0.09/GB in AWS). A single unoptimized federated query can transfer terabytes and generate unexpected bills.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Minimize cross-region queries. Use data replication (read replicas, CDC) or cache results locally. For analytics, stage data in the same region as compute resources.
