# tests/integration/test_cli.py
import subprocess
import sys

from slowql import cli


# -------------------------------
# Helpers
# -------------------------------
def run_cli(args, capsys):
    """Run CLI main() with given args and capture output + exit code."""
    try:
        cli.main(args)
    except SystemExit as e:
        return capsys.readouterr(), e.code
    return capsys.readouterr(), 0

# -------------------------------
# Core CLI Modes
# -------------------------------
def test_cli_modes(sample_sql_file, capsys):
    for args in [
        ["--no-intro", "--input-file", str(sample_sql_file)],
        ["--fast", "--no-intro", "--input-file", str(sample_sql_file)],
        ["--fast", "--no-intro", "--parallel", "--input-file", str(sample_sql_file)],
        ["--fast", "--no-intro", "--verbose", "--input-file", str(sample_sql_file)],
    ]:
        out, code = run_cli(args, capsys)
        assert code == 0
        assert "SLOWQL Analysis" in out.out

def test_cli_empty_file(empty_sql_file, capsys):
    out, code = run_cli(["--fast", "--no-intro", "--input-file", str(empty_sql_file)], capsys)
    assert code == 0
    assert "Input file is empty" in out.out

# -------------------------------
# Export Formats
# -------------------------------
def test_cli_export_formats(sample_sql_file, tmp_path, capsys):
    for fmt in ["json", "csv", "html"]:
        out_dir = tmp_path / f"reports_{fmt}"
        _, code = run_cli([
            "--fast", "--no-intro",
            "--input-file", str(sample_sql_file),
            "--export", fmt,
            "--out", str(out_dir)
        ], capsys)
        assert code == 0
        assert list(out_dir.glob(f"*.{fmt}"))

def test_cli_invalid_export_format(sample_sql_file, tmp_path, capsys):
    out, code = run_cli([
        "--fast", "--no-intro",
        "--input-file", str(sample_sql_file),
        "--export", "invalid",
        "--out", str(tmp_path)
    ], capsys)
    assert code != 0
    assert "invalid choice" in out.err or "unsupported" in out.out.lower()

# -------------------------------
# Paste Mode
# -------------------------------
def test_cli_paste_mode(monkeypatch, capsys):
    inputs = iter(["SELECT * FROM users;"])
    monkeypatch.setattr("builtins.input", lambda: next(inputs, ""))
    out, code = run_cli(["--fast", "--no-intro", "--mode", "paste"], capsys)
    assert code == 0
    assert "SLOWQL Analysis" in out.out

def test_cli_paste_mode_empty(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda: "")
    out, code = run_cli(["--fast", "--no-intro", "--mode", "paste"], capsys)
    assert code == 0
    assert "No SQL provided" in out.out or "Exiting" in out.out

# -------------------------------
# Help & Intro
# -------------------------------
def test_cli_help_flags(capsys):
    for flag, expected in [
        ("--help", "usage"),
        ("--help-art", "Visual Help"),
    ]:
        out, code = run_cli([flag], capsys)
        assert code == 0
        assert expected.lower() in out.out.lower()

def test_cli_version_output(capsys):
    out, code = run_cli(["--help"], capsys)
    assert code == 0
    assert "slowql" in out.out.lower()

def test_cli_intro_banner(sample_sql_file, capsys):
    out, code = run_cli(["--fast", "--input-file", str(sample_sql_file)], capsys)
    assert code == 0
    assert "SYSTEM ONLINE" in out.out or "Intro" in out.out

# -------------------------------
# SQL Split Edge Cases
# -------------------------------
def test_sql_split_variants():
    assert cli.sql_split_statements("") == []
    assert cli.sql_split_statements("SELECT * FROM users") == ["SELECT * FROM users"]
    assert "semi;colon" in cli.sql_split_statements("SELECT 'semi;colon';")[0]
    assert "quoted" in cli.sql_split_statements('SELECT "quoted";')[0]
    assert cli.sql_split_statements("SELECT 'abc\\'def';")[0].startswith("SELECT")

# -------------------------------
# Exception Paths
# -------------------------------
def test_intro_animation_exception(monkeypatch, sample_sql_file, capsys):
    class FakeMatrix:
        def run(self, duration=1.0):
            raise RuntimeError("boom")
    monkeypatch.setattr(cli, "MatrixRain", lambda: FakeMatrix())
    out, code = run_cli(["--input-file", str(sample_sql_file)], capsys)
    assert code == 0

def test_animated_analyzer_exception(monkeypatch, sample_sql_file, capsys):
    class FakeAA:
        def particle_loading(self, msg): raise RuntimeError("fail")
        def glitch_transition(self, duration=0.1): raise RuntimeError("fail")
        def show_expandable_details(self, summary, details, expanded=False): raise RuntimeError("fail")
    monkeypatch.setattr(cli, "AnimatedAnalyzer", lambda: FakeAA())
    out, code = run_cli(["--input-file", str(sample_sql_file)], capsys)
    assert code == 0

def test_export_failures(monkeypatch, sample_sql_file, tmp_path, capsys):
    class BadHTML(cli.ConsoleFormatter):
        def export_html_report(self, df, filename): raise RuntimeError("fail")
    monkeypatch.setattr(cli, "ConsoleFormatter", lambda: BadHTML())
    out, code = run_cli([
        "--input-file", str(sample_sql_file),
        "--export", "html",
        "--out", str(tmp_path)
    ], capsys)
    assert "Failed to export html" in out.out

    class BadCSV(cli.QueryAnalyzer):
        def export_report(self, df, format, filename): raise RuntimeError("fail")
    monkeypatch.setattr(cli, "QueryAnalyzer", lambda *a, **k: BadCSV())
    out, code = run_cli([
        "--input-file", str(sample_sql_file),
        "--export", "csv",
        "--out", str(tmp_path)
    ], capsys)
    assert "Failed to export csv" in out.out

# -------------------------------
# AnimatedAnalyzer non-fast path
# -------------------------------
def test_cli_nonfast_path(monkeypatch, sample_sql_file, capsys):
    class FakeAA:
        def particle_loading(self, msg): print("particle_loading called")
        def glitch_transition(self, duration=0.25): print(f"glitch_transition {duration}")
        def show_expandable_details(self, summary, details, expanded=False): print("details called")
    monkeypatch.setattr(cli, "AnimatedAnalyzer", lambda: FakeAA())
    out, code = run_cli(["--input-file", str(sample_sql_file)], capsys)
    assert code == 0
    assert "particle_loading called" in out.out
    assert "glitch_transition 0.25" in out.out
    assert "details called" in out.out
    assert "glitch_transition 0.35" in out.out

# -------------------------------
# __main__ entrypoint
# -------------------------------
def test_cli_main_entrypoint(sample_sql_file):
    result = subprocess.run(
        [sys.executable, "-m", "slowql.cli", "--no-intro", "--fast", "--input-file", str(sample_sql_file)],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "SLOWQL Analysis" in result.stdout
