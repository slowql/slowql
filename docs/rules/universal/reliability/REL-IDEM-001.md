# Non-Idempotent INSERT Pattern (REL-IDEM-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Non-idempotent INSERTs cause duplicate data on network retries, application restarts, or message queue redelivery. This corrupts data and breaks business logic.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use idempotent patterns: INSERT ... ON CONFLICT DO NOTHING, INSERT IGNORE, INSERT ... ON DUPLICATE KEY UPDATE, or MERGE. Include unique identifiers (UUID) from the client.
