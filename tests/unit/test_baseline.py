# tests/unit/test_baseline.py
"""
Unit tests for the SlowQL Baseline feature.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003

import pytest

from slowql.core.baseline import BaselineEntry, BaselineManager
from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Query, Severity

# ---------------------------------------------------------------------------
# Test Data Helpers
# ---------------------------------------------------------------------------

def create_issue(
    rule_id: str,
    snippet: str,
    file_path: str | None = None,
    line: int = 1,
) -> Issue:
    return Issue(
        rule_id=rule_id,
        message=f"Test issue for {rule_id}",
        severity=Severity.MEDIUM,
        dimension=Dimension.QUALITY,
        location=Location(line=line, column=1, file=file_path),
        snippet=snippet,
    )

def create_result(issues: list[Issue]) -> AnalysisResult:
    result = AnalysisResult(
        dialect="postgresql",
        config_hash="testhash"
    )
    for issue in issues:
        result.add_issue(issue)
    return result

# ---------------------------------------------------------------------------
# TestBaselineEntry
# ---------------------------------------------------------------------------

class TestBaselineEntry:
    def test_fingerprint_is_stable(self) -> None:
        issue = create_issue("PERF-001", "SELECT * FROM t", "f.sql")
        entry1 = BaselineEntry.from_issue(issue)
        entry2 = BaselineEntry.from_issue(issue)
        assert entry1.fingerprint == entry2.fingerprint
        assert len(entry1.fingerprint) == 16

    def test_fingerprint_differs_for_different_rules(self) -> None:
        issue1 = create_issue("PERF-001", "SELECT * FROM t", "f.sql")
        issue2 = create_issue("SEC-001", "SELECT * FROM t", "f.sql")
        entry1 = BaselineEntry.from_issue(issue1)
        entry2 = BaselineEntry.from_issue(issue2)
        assert entry1.fingerprint != entry2.fingerprint

    def test_fingerprint_normalises_whitespace_in_snippet(self) -> None:
        issue1 = create_issue("PERF-001", "SELECT * FROM t", "f.sql")
        issue2 = create_issue("PERF-001", "  SELECT * \nFROM t  ", "f.sql")
        entry1 = BaselineEntry.from_issue(issue1)
        entry2 = BaselineEntry.from_issue(issue2)
        assert entry1.fingerprint == entry2.fingerprint

    def test_fingerprint_handles_none_file(self) -> None:
        issue = create_issue("PERF-001", "SELECT * FROM t", None)
        entry = BaselineEntry.from_issue(issue)
        assert entry.file is None
        assert isinstance(entry.fingerprint, str)


# ---------------------------------------------------------------------------
# TestBaselineGenerate
# ---------------------------------------------------------------------------

class TestBaselineGenerate:
    def test_generate_creates_entry_per_issue(self) -> None:
        issues = [
            create_issue("R1", "S1", "f1.sql"),
            create_issue("R2", "S2", "f2.sql"),
        ]
        result = create_result(issues)
        baseline = BaselineManager.generate(result)

        assert baseline.entry_count == 2
        assert len(baseline.entries) == 2

        rule_ids = {e.rule_id for e in baseline.entries}
        assert rule_ids == {"R1", "R2"}

    def test_generate_records_version_and_timestamp(self) -> None:
        result = create_result([])
        baseline = BaselineManager.generate(result)
        assert hasattr(baseline, "slowql_version")
        assert baseline.slowql_version == result.version
        assert isinstance(baseline.created_at, str)
        # Should be an ISO format string
        parsed_time = datetime.fromisoformat(baseline.created_at)
        assert parsed_time.year == datetime.now(UTC).year

    def test_generate_empty_result_creates_empty_baseline(self) -> None:
        result = create_result([])
        baseline = BaselineManager.generate(result)
        assert baseline.entry_count == 0
        assert len(baseline.entries) == 0


# ---------------------------------------------------------------------------
# TestBaselineSaveLoad
# ---------------------------------------------------------------------------

class TestBaselineSaveLoad:
    def test_save_creates_valid_json_file(self, tmp_path: Path) -> None:
        result = create_result([create_issue("R1", "S1", "f1.sql")])
        baseline = BaselineManager.generate(result)

        path = tmp_path / ".slowql-baseline"
        BaselineManager.save(baseline, path)

        assert path.exists()
        data = json.loads(path.read_text("utf-8"))
        assert data["entry_count"] == 1
        assert len(data["entries"]) == 1
        assert data["entries"][0]["rule_id"] == "R1"

    def test_load_reads_saved_baseline(self, tmp_path: Path) -> None:
        path = tmp_path / ".slowql-baseline"
        data = {
            "slowql_version": "1.0.0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "entry_count": 1,
            "entries": [
                {"rule_id": "R1", "file": "f1.sql", "fingerprint": "abc123def4567890"}
            ]
        }
        path.write_text(json.dumps(data), "utf-8")

        baseline = BaselineManager.load(path)
        assert baseline.entry_count == 1
        assert len(baseline.entries) == 1

        entry = next(iter(baseline.entries))
        assert entry.rule_id == "R1"
        assert entry.file == "f1.sql"
        assert entry.fingerprint == "abc123def4567890"

    def test_load_raises_if_file_missing(self, tmp_path: Path) -> None:
        path = tmp_path / "missing.json"
        from slowql.core.exceptions import FileNotFoundError as SlowQLFileNotFoundError
        with pytest.raises(SlowQLFileNotFoundError):
            BaselineManager.load(path)

    def test_roundtrip_preserves_all_entries(self, tmp_path: Path) -> None:
        issues = [
            create_issue("R1", "S1", "f1.sql"),
            create_issue("R2", "S2", "f2.sql"),
        ]
        baseline = BaselineManager.generate(create_result(issues))

        path = tmp_path / ".slowql-baseline"
        BaselineManager.save(baseline, path)
        loaded = BaselineManager.load(path)

        assert loaded.entry_count == baseline.entry_count
        assert loaded.entries == baseline.entries


# ---------------------------------------------------------------------------
# TestBaselineFilterNew
# ---------------------------------------------------------------------------

class TestBaselineFilterNew:
    def test_filter_removes_baseline_issues(self) -> None:
        issue1 = create_issue("R1", "S1", "f1.sql")
        issue2 = create_issue("R2", "S2", "f2.sql")

        # Baseline contains only issue1
        baseline = BaselineManager.generate(create_result([issue1]))

        # Current run finds both
        current_result = create_result([issue1, issue2])

        new_result, suppressed = BaselineManager.filter_new(current_result, baseline)

        assert suppressed == 1
        assert len(new_result.issues) == 1
        assert new_result.issues[0].rule_id == "R2"

    def test_filter_keeps_new_issues(self) -> None:
        baseline = BaselineManager.generate(create_result([
            create_issue("R1", "S1", "f1.sql")
        ]))

        current_result = create_result([
            create_issue("R1", "S1_modified", "f1.sql"), # Changed snippet -> new issue
            create_issue("R2", "S2", "f1.sql"), # Different rule -> new issue
            create_issue("R1", "S1", "f2.sql"), # Different file -> new issue
        ])

        new_result, suppressed = BaselineManager.filter_new(current_result, baseline)

        assert suppressed == 0
        assert len(new_result.issues) == 3

    def test_filter_empty_baseline_keeps_all_issues(self) -> None:
        baseline = BaselineManager.generate(create_result([]))

        current_result = create_result([
            create_issue("R1", "S1", "f1.sql"),
            create_issue("R2", "S2", "f2.sql"),
        ])

        new_result, suppressed = BaselineManager.filter_new(current_result, baseline)

        assert suppressed == 0
        assert len(new_result.issues) == 2

    def test_filter_returns_correct_suppressed_count(self) -> None:
        # 3 identical issues (e.g. at different lines but same snippet/file/rule)
        issue1_L1 = create_issue("R1", "S1", "f1.sql", line=1)
        issue1_L2 = create_issue("R1", "S1", "f1.sql", line=2)
        issue1_L3 = create_issue("R1", "S1", "f1.sql", line=3)

        # In the baseline, they have the same fingerprint, so the frozenset will have size 1
        # But filter_new should suppress *all* occurrences that match that fingerprint.
        baseline = BaselineManager.generate(create_result([issue1_L1, issue1_L2]))

        current_result = create_result([issue1_L1, issue1_L2, issue1_L3])

        new_result, suppressed = BaselineManager.filter_new(current_result, baseline)

        assert suppressed == 3
        assert len(new_result.issues) == 0


# ---------------------------------------------------------------------------
# TestEngineAnalyzeWithBaseline
# ---------------------------------------------------------------------------

class TestEngineAnalyzeWithBaseline:
    def test_analyze_with_baseline_returns_only_new_issues(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from slowql.core.engine import SlowQL

        # 1. Create a dummy baseline
        # The file will be "test.sql" instead of None
        baseline_issue = create_issue("PERF-001", "SELECT 1", "test.sql")
        baseline = BaselineManager.generate(create_result([baseline_issue]))

        baseline_path = tmp_path / ".slowql-baseline"
        BaselineManager.save(baseline, baseline_path)

        # 2. Setup engine with monkeypatched _run_analyzers
        engine = SlowQL(auto_discover=False)

        new_issue = create_issue("SEC-001", "SELECT 2", "test.sql")

        # When engine.analyze_file is called, it will eventually call _run_analyzers
        # We make it return BOTH issues (the old one and the new one)
        def mock_run_analyzers(queries: list[Query]) -> list[Issue]:  # noqa: ARG001
            return [baseline_issue, new_issue]

        monkeypatch.setattr(engine, "_run_analyzers", mock_run_analyzers)

        # Create a dummy file for analyze_with_baseline to read
        test_file = tmp_path / "test.sql"
        test_file.write_text("SELECT 1; SELECT 2;", "utf-8")

        # 3. Call the new method
        result, suppressed_count = engine.analyze_with_baseline(
            test_file,
            baseline_path
        )

        # 4. Verify results
        assert suppressed_count == 1
        assert len(result.issues) == 1
        assert result.issues[0].rule_id == "SEC-001"

    def test_analyze_with_baseline_raises_when_file_missing(self, tmp_path: Path) -> None:
        from slowql.core.engine import SlowQL
        from slowql.core.exceptions import FileNotFoundError as SlowQLFileNotFoundError

        engine = SlowQL(auto_discover=False)
        baseline_path = tmp_path / "missing.json"

        test_file = tmp_path / "test.sql"
        test_file.write_text("SELECT 1;", "utf-8")

        with pytest.raises(SlowQLFileNotFoundError, match="Baseline file not found"):
            engine.analyze_with_baseline(test_file, baseline_path)
