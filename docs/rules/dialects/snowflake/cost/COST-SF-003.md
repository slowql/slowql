# LATERAL FLATTEN Without Warehouse Consideration (COST-SF-003)

**Dimension**: Cost
**Severity**: Info
**Scope**: Dialect Specific (Snowflake)

## Description
Undersized warehouse causes disk spilling, multiplying credit consumption.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Monitor query profile for spilling. Scale warehouse for heavy FLATTEN operations.
