# Time-Based Blind Injection Indicator (SEC-INJ-004)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Blind SQL injection allows attackers to extract data one bit at a time by measuring response delays. Even without visible output, attackers can fully compromise a database through time-based techniques.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Remove time delay functions from application queries. Use parameterized queries to prevent injection. If used for testing or scheduling, move the logic to application code outside of SQL.
