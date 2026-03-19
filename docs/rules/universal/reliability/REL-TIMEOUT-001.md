# Long-Running Query Risk (REL-TIMEOUT-001)

**Dimension**: Reliability
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
Complex queries without bounds can run for hours, consuming connections, blocking resources, and exhausting timeout-less connection pools.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Add LIMIT/TOP to bound result size. Set query timeout at connection level. Use query governor or Resource Governor. Monitor and kill long-running queries.
