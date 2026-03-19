# CASE Without ELSE (QUAL-MODERN-004)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Unmatched CASE returns NULL, which propagates through arithmetic (NULL + 1 = NULL), string operations (NULL || 'x' = NULL), and comparisons (NULL = NULL is UNKNOWN).

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always add ELSE with a sensible default: CASE WHEN x THEN y ELSE default_value END.
