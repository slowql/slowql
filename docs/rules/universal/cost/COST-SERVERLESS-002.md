# Unnecessary Connection Pooling (COST-SERVERLESS-002)

**Dimension**: Cost
**Severity**: Info
**Scope**: Universal (All Dialects)

## Description
Serverless databases charge per second of connection time. Keeping connections alive between invocations wastes money.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Close connections immediately after query in Lambda/serverless. Use RDS Proxy for connection pooling.
