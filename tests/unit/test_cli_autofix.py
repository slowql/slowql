from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from slowql.cli import app as cli_app


@pytest.fixture(autouse=True)
def silent_cli(monkeypatch):
    monkeypatch.setattr(cli_app.console, "print", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli_app.ConsoleReporter, "report", lambda _self, _result: None)


def test_non_interactive_does_not_export_session_without_flag(tmp_path, monkeypatch):
    sql_file = tmp_path / "query.sql"
    sql_file.write_text("SELECT * FROM users WHERE deleted_at IS NULL;\n", encoding="utf-8")

    calls = []

    def fake_export_session(_self, filename=None):
        calls.append(filename)
        return filename

    monkeypatch.setattr(cli_app.SessionManager, "export_session", fake_export_session)

    cli_app.main(
        [
            "--non-interactive",
            "--no-intro",
            "--input-file",
            str(sql_file),
            "--out",
            str(tmp_path / "reports"),
        ]
    )

    assert calls == []


def test_non_interactive_exports_session_when_explicit(tmp_path, monkeypatch):
    sql_file = tmp_path / "query.sql"
    sql_file.write_text("SELECT * FROM users WHERE deleted_at IS NULL;\n", encoding="utf-8")

    reports_dir = tmp_path / "reports"
    calls = []

    def fake_export_session(_self, filename=None):
        calls.append(filename)
        assert filename is not None
        Path(filename).write_text("{}", encoding="utf-8")
        return filename

    monkeypatch.setattr(cli_app.SessionManager, "export_session", fake_export_session)

    cli_app.main(
        [
            "--non-interactive",
            "--no-intro",
            "--input-file",
            str(sql_file),
            "--out",
            str(reports_dir),
            "--export-session",
        ]
    )

    assert len(calls) == 1
    assert calls[0] is not None
    exported = Path(calls[0])
    assert exported.exists()
    assert exported.parent == reports_dir


def test_fix_and_diff_cannot_be_used_together(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_app.main(["--fix", "--diff"])

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--diff and --fix cannot be used together" in captured.err


def test_fix_requires_input_file(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_app.main(["--fix"])

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--fix currently requires --input-file or a positional file" in captured.err


def test_fix_rejects_directory_input(tmp_path, capsys):
    sql_dir = tmp_path / "sql"
    sql_dir.mkdir()

    with pytest.raises(SystemExit) as exc:
        cli_app.main(["--fix", "--input-file", str(sql_dir)])

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--fix currently supports only a single file, not a directory" in captured.err


def test_fix_applies_safe_null_fix_and_creates_backup(tmp_path, monkeypatch):
    sql_file = tmp_path / "query.sql"
    original = "SELECT * FROM users WHERE deleted_at = NULL;\n"
    sql_file.write_text(original, encoding="utf-8")

    def fail_if_export_called(_self, _filename=None):
        raise AssertionError("session export should not be called without --export-session")

    monkeypatch.setattr(cli_app.SessionManager, "export_session", fail_if_export_called)

    cli_app.main(
        [
            "--non-interactive",
            "--no-intro",
            "--input-file",
            str(sql_file),
            "--out",
            str(tmp_path / "reports"),
            "--fix",
        ]
    )

    assert sql_file.read_text(encoding="utf-8") == "SELECT * FROM users WHERE deleted_at IS NULL;\n"

    backup_file = tmp_path / "query.sql.bak"
    assert backup_file.exists()
    assert backup_file.read_text(encoding="utf-8") == original

def test_diff_with_fix_report(tmp_path):
    sql_file = tmp_path / "query.sql"
    sql_file.write_text("SELECT * FROM users WHERE deleted_at = NULL;\n", encoding="utf-8")
    report_file = tmp_path / "report.json"

    cli_app.main([
        "--non-interactive", "--no-intro",
        "--input-file", str(sql_file),
        "--diff",
        "--fix-report", str(report_file)
    ])

    import json
    assert report_file.exists()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["mode"] == "diff"
    assert data["input_file"] == str(sql_file.resolve())
    assert data["backup_file"] is None
    assert data["total_fixes"] > 0
    fix = data["fixes"][0]
    assert "remediation_mode" in fix
    assert fix["remediation_mode"] == "safe_apply"
    assert fix["is_safe"] is True
    assert fix["rule_id"] == "QUAL-NULL-001"


def test_fix_with_fix_report(tmp_path, monkeypatch):
    sql_file = tmp_path / "query.sql"
    sql_file.write_text("SELECT * FROM users WHERE deleted_at = NULL;\n", encoding="utf-8")
    report_file = tmp_path / "report.json"

    def fail_if_export_called(_self, _filename=None):
        raise AssertionError("session export should not be called without --export-session")

    monkeypatch.setattr(cli_app.SessionManager, "export_session", fail_if_export_called)

    cli_app.main([
        "--non-interactive", "--no-intro",
        "--input-file", str(sql_file),
        "--fix",
        "--fix-report", str(report_file)
    ])

    import json
    assert report_file.exists()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["mode"] == "fix"
    assert data["input_file"] == str(sql_file.resolve())
    assert data["backup_file"] == str(sql_file.with_name(sql_file.name + ".bak").resolve())
    assert data["total_fixes"] > 0
    fix = data["fixes"][0]
    assert "remediation_mode" in fix
    assert fix["remediation_mode"] == "safe_apply"
    assert fix["is_safe"] is True
    assert fix["rule_id"] == "QUAL-NULL-001"


def test_no_fix_report_created_unless_explicitly_passed(tmp_path):
    sql_file = tmp_path / "query.sql"
    sql_file.write_text("SELECT * FROM users WHERE deleted_at = NULL;\n", encoding="utf-8")
    report_file = tmp_path / "should_not_exist.json"

    cli_app.main([
        "--non-interactive", "--no-intro",
        "--input-file", str(sql_file),
        "--diff"
    ])

    assert not report_file.exists()


class TestAutofixOrchestrationGaps:
    def test_collect_safe_fixes_analyzer_exception(self, monkeypatch):
        mock_engine = MagicMock()
        mock_analyzer = MagicMock()
        mock_rule = MagicMock()
        mock_analyzer.rules = [mock_rule]
        mock_analyzer.check_rule.side_effect = Exception("Analyzer crash")
        mock_engine.analyzers = [mock_analyzer]

        result = MagicMock()
        result.queries = [MagicMock()]

        fixes = cli_app._collect_safe_fixes(mock_engine, result)
        assert fixes == []

    def test_collect_safe_fixes_dedupe_and_no_remediation_mode(self, monkeypatch):
        from slowql.core.models import Fix, FixConfidence
        mock_engine = MagicMock()
        mock_analyzer = MagicMock()

        rule = MagicMock()
        # Rule has no remediation_mode attribute
        if hasattr(rule, "remediation_mode"):
            delattr(rule, "remediation_mode")

        fix = Fix(
            rule_id="RULE1",
            original="old",
            replacement="new",
            description="fix it",
            confidence=FixConfidence.SAFE
        )
        rule.suggest_fix.return_value = fix
        mock_analyzer.rules = [rule]
        mock_analyzer.check_rule.return_value = [MagicMock()]
        mock_engine.analyzers = [mock_analyzer]

        query = MagicMock()
        query.raw = "old"
        result = MagicMock()
        result.queries = [query]

        # Test dedupe: same fix twice
        fixes = cli_app._collect_safe_fixes(mock_engine, result)
        assert len(fixes) == 1
        assert len(fixes[0][1]) == 1
        assert fixes[0][1][0][1] is None  # remediation_mode is None

    def test_preview_safe_fixes_no_diff(self, monkeypatch):
        with patch("slowql.cli.app.AutoFixer") as MockAutofixer:
            MockAutofixer.return_value.preview_fixes.return_value = ""

            mock_engine = MagicMock()
            result = MagicMock()
            query = MagicMock()
            result.queries = [query]

            with (patch("slowql.cli.app._collect_safe_fixes") as mock_collect,
                  patch("slowql.cli.app.console") as mock_console):
                mock_collect.return_value = [(query, [(MagicMock(), "safe_apply")])]
                cli_app._preview_safe_fixes(mock_engine, result)

                calls = [str(c) for c in mock_console.print.call_args_list]
                assert any("No safe autofix preview available" in c for c in calls)

    def test_apply_safe_fixes_to_file_early_returns(self, tmp_path):
        mock_engine = MagicMock()
        result = MagicMock()

        with patch("slowql.cli.app.console") as mock_console:
            # 1. input_file is None
            cli_app._apply_safe_fixes_to_file(
                input_file=None, sql_payload="select 1", engine=mock_engine, result=result
            )
            calls = [str(c) for c in mock_console.print.call_args_list]
            assert any("--fix currently supports only a single input file" in c for c in calls)

            # 2. no safe fixes
            f = tmp_path / "test.sql"
            f.write_text("select 1")
            with patch("slowql.cli.app._collect_safe_fixes", return_value=[]):
                cli_app._apply_safe_fixes_to_file(
                    input_file=f, sql_payload="select 1", engine=mock_engine, result=result
                )
                calls = [str(c) for c in mock_console.print.call_args_list]
                assert any("No safe fixes available to apply" in c for c in calls)

            # 3. updated == original
            with (patch("slowql.cli.app._collect_safe_fixes") as mock_collect,
                  patch("slowql.cli.app.AutoFixer") as MockAutofixer):
                mock_collect.return_value = [(MagicMock(), [(MagicMock(), "safe_apply")])]
                MockAutofixer.return_value.apply_all_fixes.return_value = "select 1"
                cli_app._apply_safe_fixes_to_file(
                    input_file=f, sql_payload="select 1", engine=mock_engine, result=result
                )
                calls = [str(c) for c in mock_console.print.call_args_list]
                assert any("No applicable safe fixes were applied" in c for c in calls)
