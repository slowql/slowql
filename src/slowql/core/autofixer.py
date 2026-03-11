"""
Autofix engine for SlowQL.

This module provides a conservative, text-based fix application engine.
It intentionally avoids schema-aware rewrites or heuristic SQL rewriting.
Only exact, explicit replacements are supported.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import unified_diff

from slowql.core.models import Fix, FixConfidence


@dataclass(frozen=True, slots=True)
class AppliedFix:
    """Record of a successfully applied fix."""

    rule_id: str
    description: str
    confidence: str
    original: str
    replacement: str


class AutoFixer:
    """
    Conservative autofix engine.

    Safety principles:
    - only exact text replacements
    - no schema inference
    - no guessed SQL generation
    - no file writes
    """

    def apply_fix(self, query: str, fix: Fix) -> str:
        """
        Apply a single fix to a query.

        If a span is provided, the fix is applied only to that exact slice.
        Otherwise, the fixer falls back to conservative exact-text replacement.

        Args:
            query: Original SQL query text.
            fix: Fix to apply.

        Returns:
            Updated query text if applied, otherwise original query text.
        """
        updated = query

        if fix.start is not None or fix.end is not None:
            span_valid = (
                fix.start is not None
                and fix.end is not None
                and 0 <= fix.start <= fix.end <= len(query)
            )
            if span_valid:
                assert fix.start is not None
                assert fix.end is not None
                if not fix.original or query[fix.start:fix.end] == fix.original:
                    updated = query[:fix.start] + fix.replacement + query[fix.end:]
        elif fix.original and fix.original in query:
            updated = query.replace(fix.original, fix.replacement, 1)

        return updated

    def apply_all_fixes(self, query: str, fixes: list[Fix]) -> str:
        """
        Apply multiple fixes deterministically.

        Span-based fixes are applied first, from right to left, so earlier
        replacements do not shift the offsets of later ones.

        Text-based fixes are then applied conservatively using the original
        exact-text behavior.

        Args:
            query: Original SQL query text.
            fixes: List of fixes.

        Returns:
            Updated query text.
        """
        updated = query

        span_fixes = [
            fix
            for fix in fixes
            if fix.start is not None and fix.end is not None
        ]
        text_fixes = [
            fix
            for fix in fixes
            if fix.start is None and fix.end is None
        ]

        occupied: list[tuple[int, int]] = []
        ordered_spans = sorted(
            span_fixes,
            key=lambda f: (f.start, f.end),
            reverse=True,
        )

        for fix in ordered_spans:
            assert fix.start is not None
            assert fix.end is not None

            if fix.start < 0 or fix.end < fix.start or fix.end > len(query):
                continue

            if fix.original and query[fix.start:fix.end] != fix.original:
                continue

            overlaps = any(not (fix.end <= start or fix.start >= end) for start, end in occupied)
            if overlaps:
                continue

            updated = updated[:fix.start] + fix.replacement + updated[fix.end:]
            occupied.append((fix.start, fix.end))

        ordered_text = sorted(
            text_fixes,
            key=lambda f: (
                -len(f.original or ""),
                f.rule_id,
                f.description,
            ),
        )

        original_query = query
        for fix in ordered_text:
            if not fix.original:
                continue
            if fix.original not in original_query:
                continue
            if fix.original not in updated:
                continue
            updated = updated.replace(fix.original, fix.replacement, 1)

        return updated

    def preview_fixes(self, query: str, fixes: list[Fix]) -> str:
        """
        Generate a unified diff preview for applying fixes.

        Args:
            query: Original SQL query text.
            fixes: List of fixes.

        Returns:
            Unified diff string. Empty string if no changes.
        """
        updated = self.apply_all_fixes(query, fixes)

        if updated == query:
            return ""

        diff = unified_diff(
            query.splitlines(),
            updated.splitlines(),
            fromfile="original.sql",
            tofile="fixed.sql",
            lineterm="",
        )
        return "\n".join(diff)

    def generate_fix_report(self, applied: list[Fix]) -> dict[str, object]:
        """
        Generate a structured report of fixes.

        Args:
            applied: List of fixes considered applied.

        Returns:
            Serializable report dictionary.
        """
        return {
            "total_fixes": len(applied),
            "by_confidence": {
                "safe": sum(1 for f in applied if f.confidence == FixConfidence.SAFE),
                "probable": sum(1 for f in applied if f.confidence == FixConfidence.PROBABLE),
                "unsafe": sum(1 for f in applied if f.confidence == FixConfidence.UNSAFE),
                "legacy_numeric": sum(1 for f in applied if not isinstance(f.confidence, FixConfidence)),
            },
            "fixes": [
                {
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "confidence": f.confidence.value if isinstance(f.confidence, FixConfidence) else f.confidence,
                    "original": f.original,
                    "replacement": f.replacement,
                    "is_safe": f.is_safe,
                }
                for f in applied
            ],
        }
