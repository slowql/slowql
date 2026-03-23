import subprocess
from pathlib import Path


def get_changed_files(since: str | None = None) -> set[Path]:
    """
    Get a set of absolute paths to files that have changed based on git diff.

    If `since` is provided, compares HEAD to the given revision (e.g., 'main').
    Otherwise, checks for:
    - Unstaged modifications (git diff)
    - Staged modifications (git diff --cached)
    - Untracked files (git ls-files --others)

    Only files that currently exist on disk are returned.
    """
    changed_files: set[str] = set()
    try:
        if since:
            res_since = subprocess.run(
                ["git", "diff", "--name-only", f"{since}...HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res_since.returncode == 0:
                changed_files.update(res_since.stdout.splitlines())
        else:
            # Unstaged files
            res_unstaged = subprocess.run(
                ["git", "diff", "--name-only", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res_unstaged.returncode == 0:
                changed_files.update(res_unstaged.stdout.splitlines())

            # Staged files
            res_staged = subprocess.run(
                ["git", "diff", "--name-only", "--cached"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res_staged.returncode == 0:
                changed_files.update(res_staged.stdout.splitlines())

        # Untracked files (always check)
        res_untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res_untracked.returncode == 0:
            changed_files.update(res_untracked.stdout.splitlines())

    except FileNotFoundError:
        # git is not installed or available
        return set()

    # Convert to absolute paths and filter for existence
    cwd = Path.cwd()
    resolved_paths: set[Path] = set()
    for file_str in changed_files:
        if not file_str.strip():
            continue
        p = cwd / file_str.strip()
        if p.exists() and p.is_file():
            resolved_paths.add(p.resolve())

    return resolved_paths
