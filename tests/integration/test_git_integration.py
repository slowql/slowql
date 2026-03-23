from unittest.mock import MagicMock

from slowql.cli import app


def test_cli_git_diff_filter(tmp_path, monkeypatch, capsys):
    """Test that --git-diff filters out files not in changed_files."""
    monkeypatch.chdir(tmp_path)
    # Create test sql files
    f1 = tmp_path / "changed.sql"
    f2 = tmp_path / "unchanged.sql"
    f1.write_text("SELECT * FROM users;", encoding="utf-8")
    f2.write_text("SELECT id FROM missing_table;", encoding="utf-8")

    # Mock git changed files to only return changed.sql
    mock_get_changed = MagicMock(return_value={f1.resolve()})
    monkeypatch.setattr("slowql.utils.git.get_changed_files", mock_get_changed)

    # Force format to text/console so it prints Reading...
    # Run main loop with --git-diff on the tmp_path directory
    exit_code = app.main([str(tmp_path), "--git-diff", "--format", "console", "--non-interactive", "--no-intro"])

    assert exit_code == 0
    cap = capsys.readouterr()
    stdout = cap.out

    # changed.sql should be read
    assert "Reading changed.sql..." in stdout
    # unchanged.sql should be ignored
    assert "Reading unchanged.sql..." not in stdout
    # It should mention it's in git-aware mode
    assert "Git-aware mode: analyzing 1 changed file(s)." in stdout


def test_cli_since_filter(tmp_path, monkeypatch, capsys):
    """Test that --since filters correctly."""
    monkeypatch.chdir(tmp_path)
    f1 = tmp_path / "branch_file.sql"
    f2 = tmp_path / "main_file.sql"
    f1.write_text("SELECT 1;", encoding="utf-8")
    f2.write_text("SELECT 2;", encoding="utf-8")

    mock_get_changed = MagicMock(return_value={f1.resolve()})
    monkeypatch.setattr("slowql.utils.git.get_changed_files", mock_get_changed)

    exit_code = app.main([str(tmp_path), "--since", "main", "--format", "console", "--non-interactive", "--no-intro"])

    assert exit_code == 0
    mock_get_changed.assert_called_once_with(since="main")

    cap = capsys.readouterr()
    stdout = cap.out

    assert "Reading branch_file.sql..." in stdout
    assert "Reading main_file.sql..." not in stdout
