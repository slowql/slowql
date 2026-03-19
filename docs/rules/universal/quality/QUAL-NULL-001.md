# Incorrect NULL Comparison (QUAL-NULL-001)

**Dimension**: Quality
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Using = NULL or != NULL silently returns zero rows regardless of actual NULL values, causing data to appear missing and logic to fail without errors.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace '= NULL' with 'IS NULL' and '!= NULL' or '<> NULL' with 'IS NOT NULL'. Use COALESCE() if a default value is needed instead of NULL handling.
