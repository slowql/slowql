# Missing Column Comments (QUAL-DOC-001)

**Dimension**: Quality
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Missing comments mean the business meaning of columns must be reverse-engineered from code. This slows down onboarding and leads to data misuse.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add COMMENT 'description' to all column definitions. Explain units (e.g., 'price in USD') and expected values.
