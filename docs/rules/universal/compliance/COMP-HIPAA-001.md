# PHI Access Without Audit Trail (COMP-HIPAA-001)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Lack of audit trails for PHI access prevents detection of unauthorized access and violates HIPAA Technical Safeguards, potentially leading to OCR investigations and significant civil money penalties.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Ensure all queries accessing PHI are wrapped in a stored procedure or application service that performs mandatory audit logging. Consider using database-level Audit features (e.g., SQL Server Audit, Oracle Audit Vault).
