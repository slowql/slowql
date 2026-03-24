# Non-Idempotent UPDATE Pattern (REL-IDEM-002)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Relative updates like SET count = count + 1 execute multiple times on retry, causing incorrect totals. Financial calculations become inaccurate, inventory goes negative.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
