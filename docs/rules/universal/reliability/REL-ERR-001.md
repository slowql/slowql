# Swallowed Exception Pattern (REL-ERR-001)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Silent exception swallowing means failed operations appear to succeed. Data integrity violations, constraint failures, and deadlocks go undetected, leading to corrupted application state.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always re-raise or log exceptions. In Oracle PL/SQL use RAISE or RAISE_APPLICATION_ERROR. In PostgreSQL use RAISE EXCEPTION. In T-SQL use THROW or RAISERROR. Never use WHEN OTHERS THEN NULL in production code.
