# PRAGMA foreign_keys = OFF (REL-SQLITE-002)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Sqlite)

## Description
Without foreign key enforcement, INSERT and DELETE can create orphan records that violate data relationships. There is no automatic cleanup.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Set PRAGMA foreign_keys = ON at connection startup. Note: this must be set per-connection, not per-database.
