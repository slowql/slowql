# Incorrect NULL Comparison (QUAL-NULL-001)

**Dimension**: Quality
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Using = NULL or != NULL silently returns zero rows regardless of actual NULL values, causing data to appear missing and logic to fail without errors.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
