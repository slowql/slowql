# BigQuery Query Without LIMIT (COST-BQ-002)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
BigQuery bills for bytes scanned regardless of rows returned. An exploratory query without LIMIT on a large table incurs full scan cost even if you only need a sample of the data.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
