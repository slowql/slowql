# Segregation of Duties Violation (COMP-SOX-002)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
SoD violations allow a single individual to initiate and approve a financial transaction, creating a significant risk of fraud and material misstatement.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Enforce SoD at the application and database trigger level. Ensure that created_by and approved_by values are never the same for the same record.
