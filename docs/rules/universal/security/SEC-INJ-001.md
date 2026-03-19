# Potential SQL Injection (SEC-INJ-001)

**Dimension**: Security
**Severity**: Critical
**Scope**: Universal (All Dialects)

## Description
Attackers can execute arbitrary SQL commands, accessing or destroying data.

**Rationale:**
Dynamic SQL construction using concatenation is the #1 vector for SQL injection.

## Remediation / Fix
Use parameterized queries (prepared statements) instead of concatenation.
