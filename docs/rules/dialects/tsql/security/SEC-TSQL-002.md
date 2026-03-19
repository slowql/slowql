# OLE Automation (sp_OACreate) (SEC-TSQL-002)

**Dimension**: Security
**Severity**: Critical
**Scope**: Dialect Specific (Tsql)

## Description
OLE Automation enables arbitrary COM object instantiation and host compromise.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Disable OLE Automation: sp_configure 'Ole Automation Procedures', 0.
