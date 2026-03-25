# COPY Without MANIFEST (REL-RS-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Universal (All Dialects)

## Description
Without MANIFEST, any file matching the S3 prefix is loaded. Concurrent writes to the prefix can cause duplicate data or load partial files.

**Rationale:**


## Remediation / Fix
No automated or manual fix guidance is currently available for this rule.
