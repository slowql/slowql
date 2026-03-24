# UNION Without ALL — Implicit Deduplication (QUAL-MODERN-003)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
UNION deduplicates results using an expensive sort or hash operation. On large result sets this adds significant overhead compared to UNION ALL.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
