# SELECT * on Redshift Columnar Storage (PERF-RS-001)

**Dimension**: Performance
**Severity**: High
**Scope**: Dialect Specific (Redshift)

## Description
Redshift charges for bytes scanned. SELECT * on a 100-column table reads 100x more data than selecting the 1 column needed.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always specify explicit column names. Use CTAS or views to reduce column exposure.
