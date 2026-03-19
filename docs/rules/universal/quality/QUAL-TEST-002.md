# Pagination Without ORDER BY (QUAL-TEST-002)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
SQL does not guarantee row order without ORDER BY. Without it, pagination can return the same row on multiple pages or skip rows entirely, leading to UI bugs.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always add ORDER BY when using LIMIT/OFFSET. Ensure the sort key is unique (e.g., include ID) to guarantee stable sorting.
