# DBMS_SQL Dynamic Execution (SEC-ORA-002)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Oracle)

## Description
DBMS_SQL bypasses static SQL parsing, enabling arbitrary SQL execution.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use bind variables with DBMS_SQL.BIND_VARIABLE or native EXECUTE IMMEDIATE with USING.
