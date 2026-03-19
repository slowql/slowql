# Commented-Out SQL Code (QUAL-STYLE-004)

**Dimension**: Quality
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Commented-out code creates confusion about query intent, may hide dangerous statements, and bloats query logs.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove commented-out SQL fragments before deploying queries. Use version control to track historical query variants. If the code may be needed, move it to a migration or script file with context.
