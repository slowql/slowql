# Pagination Without ORDER BY (QUAL-TEST-002)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
SQL does not guarantee row order without ORDER BY. Without it, pagination can return the same row on multiple pages or skip rows entirely, leading to UI bugs.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
