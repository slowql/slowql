# slowql/src/slowql/utils/io.py
"""Input/Output utilities."""
from pathlib import Path

def read_file(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")