# Financial Data Modification Without Change Tracking (COMP-SOX-001)

**Dimension**: Compliance
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Untracked modifications to financial records violate Sarbanes-Oxley (SOX) Section 404 internal controls, potentially leading to audit failures and legal liabilities for public companies.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always include a change tracking reference (e.g., Jira ticket ID or change reason) in the query comment or as a mandatory field in the audit metadata columns.
