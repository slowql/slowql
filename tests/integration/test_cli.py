# tests/integration/test_cli.py
import subprocess
import sys

CLI_CMD = [sys.executable, "-m", "slowql.cli"]

# -------------------------------
# Helpers
# -------------------------------
def run_cli(args, cwd=None):
    """Run CLI with given args and return CompletedProcess."""
    return subprocess.run(
        CLI_CMD + args,
        capture_output=True,
        text=True,
        cwd=cwd
    )

# -------------------------------
# Core CLI Tests
# -------------------------------
def test_cli_fast_mode(sample_sql_file):
    result = run_cli(["--fast", "--no-intro", "--input-file", str(sample_sql_file)])
    assert result.returncode == 0
    assert "SLOWQL Analysis" in result.stdout

def test_cli_parallel_mode(sample_sql_file):
    result = run_cli(["--fast", "--no-intro", "--parallel", "--input-file", str(sample_sql_file)])
    assert result.returncode == 0
    assert "SLOWQL Analysis" in result.stdout

def test_cli_verbose_output(sample_sql_file):
    result = run_cli(["--fast", "--no-intro", "--verbose", "--input-file", str(sample_sql_file)])
    assert result.returncode == 0
    assert "Analyzing SQL queries" in result.stdout

def test_cli_empty_file(empty_sql_file):
    result = run_cli(["--fast", "--no-intro", "--input-file", str(empty_sql_file)])
    assert result.returncode == 0
    assert "Input file is empty" in result.stdout

def test_cli_export_json(sample_sql_file, tmp_path):
    out_dir = tmp_path / "reports"
    result = run_cli([
        "--fast", "--no-intro",
        "--input-file", str(sample_sql_file),
        "--export", "json",
        "--out", str(out_dir)
    ])
    assert result.returncode == 0
    files = list(out_dir.glob("*.json"))
    assert files, "JSON export file not created"

def test_cli_export_csv(sample_sql_file, tmp_path):
    out_dir = tmp_path / "reports"
    result = run_cli([
        "--fast", "--no-intro",
        "--input-file", str(sample_sql_file),
        "--export", "csv",
        "--out", str(out_dir)
    ])
    assert result.returncode == 0
    files = list(out_dir.glob("*.csv"))
    assert files, "CSV export file not created"

def test_cli_export_html(sample_sql_file, tmp_path):
    out_dir = tmp_path / "reports"
    result = run_cli([
        "--fast", "--no-intro",
        "--input-file", str(sample_sql_file),
        "--export", "html",
        "--out", str(out_dir)
    ])
    assert result.returncode == 0
    files = list(out_dir.glob("*.html"))
    assert files, "HTML export file not created"

# -------------------------------
# Error Handling
# -------------------------------
def test_cli_invalid_export_format(sample_sql_file, tmp_path):
    out_dir = tmp_path / "reports"
    result = run_cli([
        "--fast", "--no-intro",
        "--input-file", str(sample_sql_file),
        "--export", "invalid",
        "--out", str(out_dir)
    ])
    # Should fail gracefully with non-zero exit
    assert result.returncode != 0
    assert "invalid choice" in result.stderr or "Unsupported format" in result.stdout


def test_cli_no_sql_provided(tmp_path):
    # Run with no input file and no stdin
    result = run_cli(["--fast", "--no-intro", "--mode", "paste"], cwd=tmp_path)
    assert result.returncode == 0
    assert "No SQL provided" in result.stdout or "Exiting" in result.stdout

# -------------------------------
# Help & Intro
# -------------------------------
def test_cli_help_art_flag():
    result = run_cli(["--help-art", "--fast", "--no-intro"])
    assert result.returncode == 0
    # Should print cinematic help text
    assert "SLOWQL Visual Help" in result.stdout or "placeholder" in result.stdout


def test_cli_skip_intro(sample_sql_file):
    result = run_cli(["--no-intro", "--fast", "--input-file", str(sample_sql_file)])
    assert result.returncode == 0
    # Ensure analysis still runs without intro
    assert "SLOWQL Analysis" in result.stdout
