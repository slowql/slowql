import subprocess
from unittest.mock import MagicMock

import pytest

from slowql.utils.git import get_changed_files


@pytest.fixture
def mock_subprocess_run(monkeypatch):
    """Fixture to mock subprocess.run."""
    mock_run = MagicMock()
    monkeypatch.setattr(subprocess, "run", mock_run)
    return mock_run


def create_mock_result(stdout: str, returncode: int = 0) -> MagicMock:
    res = MagicMock()
    res.stdout = stdout
    res.returncode = returncode
    return res


def set_mock_results(mock_run: MagicMock, calls_stdout: list[str]) -> None:
    mock_run.side_effect = [create_mock_result(out) for out in calls_stdout]


def test_get_changed_files_with_since(mock_subprocess_run, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Create some dummy files
    f1 = tmp_path / "changed1.sql"
    f2 = tmp_path / "changed2.sql"
    f1.write_text("SELECT 1;")
    f2.write_text("SELECT 2;")
    # f3 is NOT created to test that deleted files are filtered out

    # We expect 2 calls: one for since...HEAD, one for untracked
    set_mock_results(
        mock_subprocess_run,
        [
            "changed1.sql\ndeleted.sql\n",  # diff since...HEAD
            "changed2.sql\n",               # untracked
        ],
    )

    result = get_changed_files(since="main")

    assert result == {f1.resolve(), f2.resolve()}
    assert mock_subprocess_run.call_count == 2
    mock_subprocess_run.assert_any_call(
        ["git", "diff", "--name-only", "main...HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    mock_subprocess_run.assert_any_call(
        ["git", "ls-files", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_get_changed_files_without_since(mock_subprocess_run, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f_unstaged = tmp_path / "unstaged.sql"
    f_staged = tmp_path / "staged.sql"
    f_untracked = tmp_path / "untracked.sql"

    f_unstaged.write_text("s")
    f_staged.write_text("s")
    f_untracked.write_text("s")

    # 3 calls: HEAD, --cached, untracked
    set_mock_results(
        mock_subprocess_run,
        [
            "unstaged.sql\n",   # HEAD diff
            "staged.sql\n",     # --cached diff
            "untracked.sql\n",  # untracked
        ],
    )

    result = get_changed_files()
    assert result == {
        f_unstaged.resolve(),
        f_staged.resolve(),
        f_untracked.resolve(),
    }
    assert mock_subprocess_run.call_count == 3


def test_get_changed_files_git_not_found(mock_subprocess_run):
    mock_subprocess_run.side_effect = FileNotFoundError()
    assert get_changed_files() == set()


def test_get_changed_files_git_fails(mock_subprocess_run, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mock_run = MagicMock()
    mock_run.returncode = 1
    mock_run.stdout = ""
    mock_subprocess_run.return_value = mock_run

    assert get_changed_files(since="main") == set()
