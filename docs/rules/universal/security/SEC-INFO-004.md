# Verbose Error Messages (SEC-INFO-004)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Error messages containing schema names, query fragments, or stack traces help attackers understand database structure and find injection points. Production errors should be generic.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Return generic error messages to users ('An error occurred. Contact support.'). Log detailed errors server-side only. Never expose query text, object names, or internal errors to clients.
