# OPENROWSET / OPENDATASOURCE Usage (SEC-TSQL-001)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Tsql)

## Description
OPENROWSET can read from arbitrary OLE DB sources including file system.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Disable Ad Hoc Distributed Queries. Use linked servers with restricted permissions.
