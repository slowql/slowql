"""Redshift-specific reliability rules."""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "CopyWithoutManifestRule",
]


class CopyWithoutManifestRule(PatternRule):
    """Detects COPY without MANIFEST on Redshift."""

    id = "REL-RS-001"
    name = "COPY Without MANIFEST"
    description = (
        "COPY without MANIFEST loads all files matching the S3 prefix. "
        "This can accidentally load duplicate or unexpected files if new "
        "files appear in the prefix during or between loads."
    )
    severity = Severity.HIGH
    dimension = Dimension.RELIABILITY
    category = Category.REL_DATA_INTEGRITY
    dialects = ("redshift",)

    pattern = r"\bCOPY\b.*\bFROM\b.*\bs3://(?!.*\bMANIFEST\b)"
    message_template = "COPY from S3 without MANIFEST — may load unexpected files: {match}"

    impact = (
        "Without MANIFEST, any file matching the S3 prefix is loaded. "
        "Concurrent writes to the prefix can cause duplicate data or "
        "load partial files."
    )
    fix_guidance = (
        "Use COPY ... FROM 's3://bucket/manifest.json' MANIFEST to load "
        "only explicitly listed files. Generate manifest with UNLOAD or "
        "your ETL pipeline."
    )
