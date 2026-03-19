# Sensitive Data in Error Output (SEC-LOG-001)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Sensitive data in error messages may be logged, displayed to users, or sent to monitoring systems. Error logs often have weaker access controls than databases.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use generic error messages for user-facing output. Log sensitive context only to secure audit logs with strict access controls. Mask sensitive values in all output.
