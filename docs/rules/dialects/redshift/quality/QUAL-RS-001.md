# DISTSTYLE ALL on Large Table (QUAL-RS-001)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Dialect Specific (Redshift)

## Description
Every INSERT, UPDATE, DELETE replicates to all nodes. For large tables this multiplies write time and storage by the cluster size.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use DISTSTYLE ALL only for small dimension tables (<1M rows). For large tables use DISTSTYLE KEY or DISTSTYLE EVEN.
