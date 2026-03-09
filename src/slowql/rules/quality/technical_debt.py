from __future__ import annotations

"""
Quality Technical debt rules.
"""

import re
from typing import Any

import sqlglot.expressions as exp
from sqlglot import exp

from slowql.core.models import Category, Dimension, Fix, Issue, Location, Query, Severity
from slowql.rules.base import ASTRule, PatternRule, Rule

__all__ = [
    'TempTableNotCleanedUpRule',
    'TodoFixmeCommentRule',
]


class TodoFixmeCommentRule(PatternRule):
    """Detects TODO or FIXME in query comments."""

    id = "QUAL-DEBT-001"
    name = "Technical Debt Marker"
    description = "Detects TODO or FIXME markers in query comments, indicating unresolved issues."
    severity = Severity.INFO
    dimension = Dimension.QUALITY
    category = Category.QUAL_TECH_DEBT

    pattern = r'\b(TODO|FIXME|XXX|HACK)\b'

    impact = (
        "TODO/FIXME markers represent known bugs or missing features that haven't been "
        "tracked in an issue tracker. They often rot and become obsolete while the issues remain."
    )
    fix_guidance = (
        "Resolve the underlying issue or move the task to a formal issue tracking system. "
        "Unresolved notes in code hinder long-term maintainability."
    )


class TempTableNotCleanedUpRule(PatternRule):
    """Detects creation of temp tables without subsequent DROP."""

    id = "QUAL-DEBT-002"
    name = "Permanent Temporary Table"
    description = "Detects CREATE TEMP TABLE without a corresponding DROP TABLE in the same unit."
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_TECH_DEBT

    pattern = r'CREATE\s+(?:TEMPORARY|TEMP)\s+TABLE\s+(\w+)(?:(?!DROP\s+TABLE\s+\1).)*\Z'

    impact = (
        "Temporary tables that aren't dropped consume memory and disk space in the temporary "
        "tablespace. Over time, they can cause disk full errors and slow down the database."
    )
    fix_guidance = (
        "Always DROP temporary tables as soon as they are no longer needed. Use 'ON COMMIT DROP' "
        "if supported by your database."
    )
