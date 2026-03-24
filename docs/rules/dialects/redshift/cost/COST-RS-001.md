# UNLOAD Without PARALLEL Consideration (COST-RS-001)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Redshift)

## Description
Default PARALLEL ON creates many small S3 files. For downstream consumers expecting a single file, this requires extra processing.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
