# slowql/src/slowql/core/baseline.py
"""
Baseline (Diff Mode) system for SlowQL.

Allows generating a baseline snapshot of existing issues, saving it to disk,
and using it in subsequent runs to only report new issues.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003
from typing import Any

from slowql.core.exceptions import FileNotFoundError
from slowql.core.models import AnalysisResult, Issue


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """A single issue fingerprint in a baseline."""
    rule_id: str
    file: str | None
    fingerprint: str

    @classmethod
    def from_issue(cls, issue: Issue) -> BaselineEntry:
        """Create a BaselineEntry from an Issue."""
        return cls(
            rule_id=issue.rule_id,
            file=issue.location.file,
            fingerprint=cls._compute_fingerprint(issue.rule_id, issue.location.file, issue.snippet)
        )

    @classmethod
    def _compute_fingerprint(cls, rule_id: str, file: str | None, snippet: str) -> str:
        """
        Compute a stable SHA-256 fingerprint from rule_id, file, and snippet.
        Whitespace in the snippet is normalized. Line numbers are intentionally excluded
        so the fingerprint survives line drift.
        """
        norm_rule_id = rule_id.upper()
        norm_file = file or ""
        norm_snippet = " ".join(snippet.split())

        payload = f"{norm_rule_id}|{norm_file}|{norm_snippet}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

@dataclass(frozen=True)
class Baseline:
    """A snapshot of all known issues at a specific point in time."""
    slowql_version: str
    created_at: str
    entry_count: int
    entries: frozenset[BaselineEntry] = field(default_factory=frozenset)

class BaselineManager:
    """Manages baseline generation, persistence, and filtering."""

    @staticmethod
    def generate(result: AnalysisResult) -> Baseline:
        """Generate a baseline snapshot from an analysis result."""
        entries = frozenset(BaselineEntry.from_issue(issue) for issue in result.issues)
        utc_now = datetime.now(UTC).isoformat()

        return Baseline(
            slowql_version=result.version,
            created_at=utc_now,
            entry_count=len(entries),
            entries=entries
        )

    @staticmethod
    def save(baseline: Baseline, path: Path) -> None:
        """Save a baseline to a JSON file."""
        path = path.resolve()

        data: dict[str, Any] = {
            "slowql_version": baseline.slowql_version,
            "created_at": baseline.created_at,
            "entry_count": baseline.entry_count,
            "entries": [
                {
                    "rule_id": e.rule_id,
                    "file": e.file,
                    "fingerprint": e.fingerprint
                } for e in baseline.entries
            ]
        }

        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def load(path: Path) -> Baseline:
        """
        Load a baseline from a JSON file.
        Raises FileNotFoundError if the file does not exist.
        """
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Baseline file not found: {path}")

        data = json.loads(path.read_text(encoding="utf-8"))

        entries = frozenset(
            BaselineEntry(
                rule_id=e["rule_id"],
                file=e.get("file"),
                fingerprint=e["fingerprint"]
            )
            for e in data.get("entries", [])
        )

        return Baseline(
            slowql_version=data.get("slowql_version", "unknown"),
            created_at=data.get("created_at", "unknown"),
            entry_count=data.get("entry_count", len(entries)),
            entries=entries
        )

    @staticmethod
    def filter_new(result: AnalysisResult, baseline: Baseline) -> tuple[AnalysisResult, int]:
        """
        Filter an AnalysisResult, keeping only issues not present in the baseline.
        Returns a (new_result, baseline_suppressed_count) tuple.
        """
        new_result = AnalysisResult(
            dialect=result.dialect,
            queries=result.queries,
            config_hash=result.config_hash
        )
        # Preserve original suppressed count (e.g. from inline suppression)
        new_result.suppressed_count = getattr(result, "suppressed_count", 0)

        # Preserve stats timing from the original result to keep them accurate
        new_result.statistics.parse_time_ms = result.statistics.parse_time_ms
        new_result.statistics.analysis_time_ms = result.statistics.analysis_time_ms

        baseline_suppressed_count = 0

        for issue in result.issues:
            entry = BaselineEntry.from_issue(issue)
            if entry in baseline.entries:
                baseline_suppressed_count += 1
                # Do NOT add to new_result.issues
            else:
                new_result.add_issue(issue)

        return new_result, baseline_suppressed_count
