"""
Quality Null handling rules.
"""

from __future__ import annotations

import re
from typing import Any

from sqlglot import exp

from slowql.core.models import (
    Category,
    Dimension,
    Fix,
    FixConfidence,
    Issue,
    Query,
    RemediationMode,
    Severity,
)
from slowql.rules.base import ASTRule, PatternRule

__all__ = [
    "CaseWithoutElseRule",
    "NullComparisonRule",
]


class NullComparisonRule(PatternRule):
    """Detects incorrect NULL comparisons using = or != instead of IS NULL / IS NOT NULL."""

    id = "QUAL-NULL-001"
    name = "Incorrect NULL Comparison"
    description = (
        "Detects comparisons using = NULL or != NULL (and <> NULL) instead of "
        "IS NULL or IS NOT NULL. In SQL, NULL = NULL evaluates to NULL (unknown), "
        "not TRUE, so these comparisons always return no rows."
    )
    severity = Severity.HIGH
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    remediation_mode = RemediationMode.SAFE_APPLY

    pattern = (
        r"(?<![A-Z_])\s*=\s*NULL\b"
        r"|\bNULL\s*=\s*(?![A-Z_])"
        r"|!=\s*NULL\b"
        r"|<>\s*NULL\b"
    )
    message_template = "Incorrect NULL comparison detected — use IS NULL or IS NOT NULL: {match}"

    impact = (
        "Using = NULL or != NULL silently returns zero rows regardless of actual "
        "NULL values, causing data to appear missing and logic to fail without errors."
    )
    fix_guidance = (
        "Replace '= NULL' with 'IS NULL' and '!= NULL' or '<> NULL' with "
        "'IS NOT NULL'. Use COALESCE() if a default value is needed instead of NULL handling."
    )

    def suggest_fix(self, query: Query) -> Fix | None:
        try:
            # != NULL / <> NULL → IS NOT NULL
            m = re.search(r"(!= NULL|<> NULL)", query.raw, re.IGNORECASE)
            if m:
                return Fix(
                    description="Replace '!= NULL' / '<> NULL' with 'IS NOT NULL'",
                    original=m.group(0),
                    replacement="IS NOT NULL",
                    confidence=FixConfidence.SAFE,
                    rule_id=self.id,
                    is_safe=True,
                )
            # = NULL → IS NULL (must come after != check to avoid partial match)
            m = re.search(r"(?<![!<>])=\s*NULL\b", query.raw, re.IGNORECASE)
            if m:
                return Fix(
                    description="Replace '= NULL' with 'IS NULL'",
                    original=m.group(0),
                    replacement="IS NULL",
                    confidence=FixConfidence.SAFE,
                    rule_id=self.id,
                    is_safe=True,
                )
        except Exception:
            return None
        return None



class CaseWithoutElseRule(ASTRule):
    """Detects CASE expressions without ELSE clause."""

    id = "QUAL-MODERN-004"
    name = "CASE Without ELSE"
    description = (
        "A CASE expression without ELSE returns NULL when no condition "
        "matches. This is a frequent source of unexpected NULLs that "
        "propagate through calculations and break NOT NULL constraints."
    )
    severity = Severity.LOW
    dimension = Dimension.QUALITY
    category = Category.QUAL_READABILITY
    dialects = ()

    impact = (
        "Unmatched CASE returns NULL, which propagates through arithmetic "
        "(NULL + 1 = NULL), string operations (NULL || 'x' = NULL), and "
        "comparisons (NULL = NULL is UNKNOWN)."
    )
    fix_guidance = (
        "Always add ELSE with a sensible default: "
        "CASE WHEN x THEN y ELSE default_value END."
    )

    def check_ast(self, query: Query, ast: Any) -> list[Issue]:
        issues = []
        for node in ast.walk():
            if isinstance(node, exp.Case):
                # Check for ELSE clause
                default = node.args.get("default")
                if default is None:
                    issues.append(self.create_issue(
                        query=query,
                        message="CASE without ELSE — returns NULL when no condition matches.",
                        snippet=str(node)[:80],
                    ))
        return issues
