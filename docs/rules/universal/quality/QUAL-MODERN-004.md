# CASE Without ELSE (QUAL-MODERN-004)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Unmatched CASE returns NULL, which propagates through arithmetic (NULL + 1 = NULL), string operations (NULL || 'x' = NULL), and comparisons (NULL = NULL is UNKNOWN).

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
