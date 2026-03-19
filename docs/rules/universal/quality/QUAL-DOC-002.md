# Magic Constant Without Comment (QUAL-DOC-002)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
Magic constants like 'STATUS_42' or 1001 represent business logic that is opaque to future maintainers. Without comments, it's impossible to know if the value is correct.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add an inline comment explaining what the constant represents. E.g., WHERE status = 'A' -- A = Active.
