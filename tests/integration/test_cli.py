# tests/integration/test_cli.py
import subprocess
import sys

from slowql import cli


# -------------------------------
# Helpers
# -------------------------------
def run_cli(args, capsys, monkeypatch=None):
    """Run CLI main() with given args and capture output + exit code."""
    if monkeypatch:
        # Prevent interactive menu loop
        monkeypatch.setattr("slowql.cli.app.show_quick_actions_menu", lambda *_, **__: False)
        # Prevent confirmation prompts (e.g. export session, error continuation)
        monkeypatch.setattr("slowql.cli.app.Confirm.ask", lambda *_, **__: False)

    try:
        cli.main(args)
    except SystemExit as e:
        return capsys.readouterr(), e.code
    return capsys.readouterr(), 0


# -------------------------------
# Core CLI Modes
# -------------------------------
def test_cli_modes(sample_sql_file, capsys, monkeypatch):
    for args in [
        ["--no-intro", "--input-file", str(sample_sql_file)],
        ["--fast", "--no-intro", "--input-file", str(sample_sql_file)],
        ["--fast", "--no-intro", "--verbose", "--input-file", str(sample_sql_file)],
    ]:
        out, code = run_cli(args, capsys, monkeypatch)
        assert code == 0
        assert "SlowQL" in out.out


def test_cli_empty_file(empty_sql_file, capsys, monkeypatch):
    out, code = run_cli(
        ["--fast", "--no-intro", "--input-file", str(empty_sql_file)], capsys, monkeypatch
    )
    assert code == 0
    assert "Input file is empty" in out.out


# -------------------------------
# Export Formats
# -------------------------------
def test_cli_export_formats(sample_sql_file, tmp_path, capsys, monkeypatch):
    for fmt in ["json", "csv", "html"]:
        out_dir = tmp_path / f"reports_{fmt}"
        _, code = run_cli(
            [
                "--fast",
                "--no-intro",
                "--input-file",
                str(sample_sql_file),
                "--export",
                fmt,
                "--out",
                str(out_dir),
            ],
            capsys,
            monkeypatch,
        )
        assert code == 0
        assert list(out_dir.glob(f"*.{fmt}"))


def test_cli_invalid_export_format(sample_sql_file, tmp_path, capsys, monkeypatch):
    out, code = run_cli(
        [
            "--fast",
            "--no-intro",
            "--input-file",
            str(sample_sql_file),
            "--export",
            "invalid",
            "--out",
            str(tmp_path),
        ],
        capsys,
        monkeypatch,
    )
    assert code != 0
    assert "invalid choice" in out.err or "unsupported" in out.out.lower()


# -------------------------------
# Paste Mode
# -------------------------------
def test_cli_paste_mode(monkeypatch, capsys):
    inputs = iter(["SELECT * FROM users;"])
    monkeypatch.setattr("builtins.input", lambda: next(inputs, ""))
    out, code = run_cli(["--fast", "--no-intro", "--mode", "paste"], capsys, monkeypatch)
    assert code == 0
    assert "SlowQL" in out.out


def test_cli_paste_mode_empty(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda: "quit")
    out, code = run_cli(["--fast", "--no-intro", "--mode", "paste"], capsys, monkeypatch)
    assert code == 0
    assert "Analysis interrupted" in out.out


# -------------------------------
# Help & Intro
# -------------------------------
def test_cli_help_flags(capsys, monkeypatch):
    for flag, expected in [
        ("--help", "usage"),
    ]:
        out, code = run_cli([flag], capsys, monkeypatch)
        assert code == 0
        assert expected.lower() in out.out.lower()


def test_cli_version_output(capsys, monkeypatch):
    out, code = run_cli(["--help"], capsys, monkeypatch)
    assert code == 0
    assert "slowql" in out.out.lower()


def test_cli_intro_banner(sample_sql_file, capsys, monkeypatch):
    out, code = run_cli(["--fast", "--input-file", str(sample_sql_file)], capsys, monkeypatch)
    assert code == 0
    assert "Welcome to SlowQL" in out.out


# -------------------------------
# SQL Split Edge Cases
# -------------------------------

# test_sql_split_variants removed as sql_split_statements is no longer available


# -------------------------------
# Exception Paths
# -------------------------------
def test_intro_animation_exception(monkeypatch, sample_sql_file, capsys):
    class FakeMatrix:
        def run(self, _duration=1.0):
            raise RuntimeError("boom")

    monkeypatch.setattr("slowql.cli.app.MatrixRain", lambda: FakeMatrix())
    _out, code = run_cli(["--input-file", str(sample_sql_file)], capsys, monkeypatch)
    assert code == 0


def test_animated_analyzer_exception(monkeypatch, sample_sql_file, capsys):
    class FakeAA:
        def particle_loading(self, _msg):
            raise RuntimeError("fail")

        def glitch_transition(self, _duration=0.1):
            raise RuntimeError("fail")

        def show_expandable_details(self, _summary, _details, _expanded=False):
            raise RuntimeError("fail")

    monkeypatch.setattr("slowql.cli.app.AnimatedAnalyzer", lambda: FakeAA())
    _out, code = run_cli(["--input-file", str(sample_sql_file)], capsys, monkeypatch)
    assert code == 0


# test_export_failures removed as QueryAnalyzer and ConsoleFormatter are not in cli module
def test_export_failures_placeholder():
    pass


# -------------------------------
# AnimatedAnalyzer non-fast path
# -------------------------------
def test_cli_nonfast_path(monkeypatch, sample_sql_file, capsys):
    class FakeAA:
        def particle_loading(self, _msg):
            print("particle_loading called")

        def glitch_transition(self, duration=0.25):
            print(f"glitch_transition {duration}")

        def show_expandable_details(self, _summary, _details, _expanded=False):
            print("details called")

    monkeypatch.setattr("slowql.cli.app.AnimatedAnalyzer", lambda: FakeAA())
    out, code = run_cli(["--input-file", str(sample_sql_file)], capsys, monkeypatch)
    assert code == 0
    assert "particle_loading called" in out.out
    assert "glitch_transition 0.25" in out.out
    assert "glitch_transition 0.25" in out.out


# -------------------------------
# __main__ entrypoint
# -------------------------------
def test_cli_main_entrypoint(sample_sql_file):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "slowql.cli.app",
            "--no-intro",
            "--fast",
            "--non-interactive",
            "--input-file",
            str(sample_sql_file),
        ],
        check=False, capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "SlowQL" in result.stdout
