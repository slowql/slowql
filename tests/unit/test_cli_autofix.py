from pathlib import Path

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
