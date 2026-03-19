# Regex Denial of Service (ReDoS) (SEC-DOS-002)

**Dimension**: Security
**Severity**: Medium
**Scope**: Universal (All Dialects)

## Description
ReDoS patterns like (a+)+ or (.*)* can take exponential time on crafted input. A single malicious input can hang database threads for hours.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use RE2-compatible patterns only (no backreferences, atomic groups). Set regex timeouts. Validate regex patterns before accepting user input.
