# EXECUTE IMMEDIATE With Concatenation (SEC-ORA-003)

**Dimension**: Security
**Severity**: Critical
**Scope**: Dialect Specific (Oracle)

## Description
String concatenation in EXECUTE IMMEDIATE allows arbitrary SQL injection.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use bind variables: EXECUTE IMMEDIATE 'SELECT * FROM t WHERE id = :1' USING v_id.
