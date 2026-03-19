# ORDER BY on VARIANT Column (PERF-SF-002)

**Dimension**: Performance
**Severity**: Low
**Scope**: Dialect Specific (Snowflake)

## Description
VARIANT sorting inspects type per row, adding significant overhead.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Cast in ORDER BY: ORDER BY data:field::NUMBER.
