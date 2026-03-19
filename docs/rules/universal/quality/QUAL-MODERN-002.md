# Hardcoded Date Literal in Filter (QUAL-MODERN-002)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Hardcoded dates become stale and cause queries to return unexpected results or no results as time passes. They also prevent query plan reuse.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Replace hardcoded dates with parameterized values (?), bind variables (:date), or dynamic expressions like NOW(), CURRENT_DATE, or CURRENT_DATE - INTERVAL '30 days'.
