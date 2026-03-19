# Overprivileged Execution Context (SEC-PRIV-001)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Stored procedures running as high-privilege accounts can be exploited for privilege escalation. WITH ADMIN/GRANT OPTION creates uncontrolled permission propagation where any granted user can re-grant to others.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use EXECUTE AS CALLER or SECURITY INVOKER instead of DEFINER/OWNER. Avoid WITH ADMIN OPTION and WITH GRANT OPTION unless absolutely necessary. Run stored procedures with the minimum privileges required. Audit all objects running as dbo or sa.
