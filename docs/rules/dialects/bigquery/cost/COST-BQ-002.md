# BigQuery Query Without LIMIT (COST-BQ-002)

**Dimension**: Cost
**Severity**: Medium
**Scope**: Dialect Specific (Bigquery)

## Description
BigQuery bills for bytes scanned regardless of rows returned. An exploratory query without LIMIT on a large table incurs full scan cost even if you only need a sample of the data.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add LIMIT for exploratory queries: SELECT * FROM t LIMIT 1000. Use table previews in the console for sampling. Use _PARTITIONTIME or _PARTITIONDATE filters to limit scan range.
