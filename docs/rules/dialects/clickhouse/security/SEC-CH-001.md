# ClickHouse url() Table Function (SEC-CH-001)

**Dimension**: Security
**Severity**: High
**Scope**: Dialect Specific (Clickhouse)

## Description
url() can reach internal services, cloud metadata endpoints (169.254.169.254), and exfiltrate data via HTTP requests.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Restrict url() with allowed_hosts in config.xml. Use named collections for approved external sources. Audit all url() usage.
