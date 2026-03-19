# Missing Covering Index Opportunity (COST-IDX-003)

**Dimension**: Cost
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Non-covering indexes require key lookup - reading index then reading table. Covering indexes eliminate table access, reducing I/O by 50-90%.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Create covering index: CREATE INDEX idx_name ON table(where_cols) INCLUDE (select_cols). Monitor index size vs benefit.
