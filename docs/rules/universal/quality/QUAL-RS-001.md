# DISTSTYLE ALL on Large Table (QUAL-RS-001)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Every INSERT, UPDATE, DELETE replicates to all nodes. For large tables this multiplies write time and storage by the cluster size.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
