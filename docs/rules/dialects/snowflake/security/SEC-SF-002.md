# CLONE Without COPY GRANTS (SEC-SF-002)

**Dimension**: Security
**Severity**: Medium
**Scope**: Dialect Specific (Snowflake)

## Description
The cloned object inherits default role permissions instead of the source's grants. Sensitive data may become accessible to unauthorized roles.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add COPY GRANTS: CREATE TABLE t_clone CLONE t COPY GRANTS.
