# Missing Primary Key (QUAL-SCHEMA-001)

**Dimension**: Quality
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Tables without primary keys are a major design flaw. They prevent row uniqueness, break replication, make updates slow, and hinder most database optimizations.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add a PRIMARY KEY to the table. Usually an auto-incrementing ID or a UUID. Every table must have a unique identifier.
