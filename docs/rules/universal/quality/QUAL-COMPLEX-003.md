# God Query (QUAL-COMPLEX-003)

**Dimension**: Quality
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
God queries try to do everything in one statement. They're slow, hard to optimize, impossible to test, and unmaintainable. Often leads to unpredictable performance.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Break into multiple focused queries. Use temp tables for intermediate results. Separate data retrieval from business logic. Aim for < 5 JOINs per query.
