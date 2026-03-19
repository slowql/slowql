# Cyclomatic Complexity in Stored Procedure (QUAL-COMPLEX-004)

**Dimension**: Quality
**Severity**: Low
**Scope**: Universal (All Dialects)

## Description
High cyclomatic complexity means many code paths, making testing exponentially harder. Bugs hide in untested branches. Overly complex logic is hard to maintain.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Extract complex logic into smaller functions. Use lookup tables instead of IF chains. Limit to 10 branches per procedure. Aim for cyclomatic complexity < 10.
