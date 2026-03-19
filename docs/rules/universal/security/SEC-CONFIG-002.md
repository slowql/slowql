# Weak SSL/TLS Configuration (SEC-CONFIG-002)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Disabling SSL/TLS exposes all data in transit to interception. Man-in-the-middle attacks can capture credentials, session tokens, and sensitive data. Required by PCI-DSS, HIPAA.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Always use encrypted connections: Encrypt=True, sslmode=require. Use certificate validation: TrustServerCertificate=False. Enforce TLS 1.2+ minimum version.
