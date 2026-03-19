# COPY Without MANIFEST (REL-RS-001)

**Dimension**: Reliability
**Severity**: High
**Scope**: Dialect Specific (Redshift)

## Description
Without MANIFEST, any file matching the S3 prefix is loaded. Concurrent writes to the prefix can cause duplicate data or load partial files.

**Rationale:**
Documentation for this rule's rationale is pending.

## Remediation / Fix
Use COPY ... FROM 's3://bucket/manifest.json' MANIFEST to load only explicitly listed files. Generate manifest with UNLOAD or your ETL pipeline.
