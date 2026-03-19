# Path Traversal in File Operations (SEC-PATH-001)

**Dimension**: Security
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Path traversal allows attackers to read/write arbitrary files on the server. Reading /etc/passwd or C:\Windows\System32\config\SAM exposes credentials. Writing enables code execution.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Validate file paths against whitelist. Use absolute paths only. Reject paths containing ../ or ..\. Sandbox file operations to specific directory. Use path canonicalization and verify result.
