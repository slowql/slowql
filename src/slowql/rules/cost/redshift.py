"""Redshift-specific cost rules."""

from __future__ import annotations

from slowql.core.models import Category, Dimension, Severity
from slowql.rules.base import PatternRule

__all__ = [
    "UnloadWithoutParallelRule",
]


class UnloadWithoutParallelRule(PatternRule):
    """Detects UNLOAD without PARALLEL consideration on Redshift."""

    id = "COST-RS-001"
    name = "UNLOAD Without PARALLEL Consideration"
    description = (
        "Redshift UNLOAD defaults to PARALLEL ON which creates multiple "
        "files. For small result sets, PARALLEL OFF creates a single file "
        "and avoids S3 request overhead."
    )
    severity = Severity.MEDIUM
    dimension = Dimension.COST
    category = Category.COST_STORAGE
    dialects = ("redshift",)

    pattern = r"\bUNLOAD\b(?!.*\bPARALLEL\b)"
    message_template = "UNLOAD without explicit PARALLEL setting: {match}"

    impact = (
        "Default PARALLEL ON creates many small S3 files. For downstream "
        "consumers expecting a single file, this requires extra processing."
    )
    fix_guidance = (
        "Add PARALLEL OFF for single-file output (small results) or "
        "PARALLEL ON MAXFILESIZE for controlled output (large results)."
    )
