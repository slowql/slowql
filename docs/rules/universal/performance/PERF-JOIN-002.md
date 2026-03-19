# Excessive Joins (PERF-JOIN-002)

**Dimension**: Performance
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
High join count increases query plan complexity and memory usage

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Consider breaking into CTEs or denormalizing hot query paths
