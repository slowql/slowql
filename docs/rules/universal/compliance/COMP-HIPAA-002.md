# PHI Minimum Necessary Violation (COMP-HIPAA-002)

**Dimension**: Compliance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Fetching all columns from healthcare tables often retrieves unnecessary protected health information, increasing the risk and scope of a potential data breach.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Explicitly list only the columns required for the specific business function. Avoid using SELECT * on tables containing PHI.
