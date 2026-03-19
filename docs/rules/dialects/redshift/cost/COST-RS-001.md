# UNLOAD Without PARALLEL Consideration (COST-RS-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Redshift)

## Description
Default PARALLEL ON creates many small S3 files. For downstream consumers expecting a single file, this requires extra processing.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add PARALLEL OFF for single-file output (small results) or PARALLEL ON MAXFILESIZE for controlled output (large results).
