# Complex Logic Without Explanation (QUAL-DOC-003)

**Dimension**: Quality
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Queries over 20 lines without comments are 'write-only' code. They are prohibitively expensive to modify or peer-review safely.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add header comments explaining the query's goal. Use inline comments for complex JOIN conditions or business logic branches.
