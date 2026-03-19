# UNION Without ALL — Implicit Deduplication (QUAL-MODERN-003)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
UNION deduplicates results using an expensive sort or hash operation. On large result sets this adds significant overhead compared to UNION ALL.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
If the result sets cannot contain meaningful duplicates, replace UNION with UNION ALL. If deduplication is required, keep UNION and add a comment explaining why to prevent future 'optimization' regressions.
