# Audit Trail Manipulation (SEC-LOG-002)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Audit log tampering destroys forensic capability and violates every compliance framework. Attackers delete logs to cover tracks. This is often evidence of active compromise.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Make audit tables append-only (no UPDATE/DELETE permissions). Use separate audit database with restricted access. Implement real-time log shipping to immutable storage.
