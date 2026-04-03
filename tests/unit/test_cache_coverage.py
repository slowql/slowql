"""Targeted coverage tests for cache.py uncovered lines."""
from __future__ import annotations

import tempfile
from pathlib import Path

from slowql.core.cache import CacheManager
from slowql.core.models import AnalysisResult


def _make_result() -> AnalysisResult:
    return AnalysisResult(dialect="postgresql", config_hash="abc123")


def test_cache_creates_gitignore():
    """Covers: gitignore creation in __init__."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir) / "test_cache"
        CacheManager(cache_dir)
        gitignore = cache_dir / ".gitignore"
        assert gitignore.exists()
        assert "*" in gitignore.read_text()


def test_cache_miss_returns_none():
    """Covers: cache_file.exists() → False branch in get()."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CacheManager(Path(tmpdir) / "cache")
        result = manager.get(Path("nonexistent.sql"), "SELECT 1", "hash123")
        assert result is None


def test_cache_set_and_get_roundtrip():
    """Covers: set() write and get() read happy path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CacheManager(Path(tmpdir) / "cache")
        sql_file = Path(tmpdir) / "test.sql"
        sql_file.write_text("SELECT 1")
        content = sql_file.read_text()
        result = _make_result()

        manager.set(sql_file, content, "hash123", result)
        cached = manager.get(sql_file, content, "hash123")

        assert cached is not None
        assert cached.dialect == "postgresql"


def test_cache_corrupted_file_returns_none():
    """Covers: except Exception in get() — corrupted cache."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CacheManager(Path(tmpdir) / "cache")
        sql_file = Path(tmpdir) / "test.sql"
        sql_file.write_text("SELECT 1")
        content = "SELECT 1"

        # Manually write corrupted cache file
        key = manager._get_cache_key(sql_file, content, "hash123")
        cache_file = manager.cache_dir / f"{key}.cache"
        cache_file.write_bytes(b"corrupted data not valid pickle")

        result = manager.get(sql_file, content, "hash123")
        assert result is None


def test_cache_clear_removes_files():
    """Covers: clear() method."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CacheManager(Path(tmpdir) / "cache")
        sql_file = Path(tmpdir) / "test.sql"
        sql_file.write_text("SELECT 1")

        manager.set(sql_file, "SELECT 1", "hash123", _make_result())
        cache_files_before = list(manager.cache_dir.glob("*.cache"))
        assert len(cache_files_before) > 0

        manager.clear()
        cache_files_after = list(manager.cache_dir.glob("*.cache"))
        assert len(cache_files_after) == 0


def test_cache_different_content_different_key():
    """Covers: _get_cache_key hashing uniqueness."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CacheManager(Path(tmpdir) / "cache")
        f = Path(tmpdir) / "f.sql"
        key1 = manager._get_cache_key(f, "SELECT 1", "hash")
        key2 = manager._get_cache_key(f, "SELECT 2", "hash")
        assert key1 != key2


def test_cache_different_config_different_key():
    """Covers: config_hash impact on cache key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = CacheManager(Path(tmpdir) / "cache")
        f = Path(tmpdir) / "f.sql"
        key1 = manager._get_cache_key(f, "SELECT 1", "config_a")
        key2 = manager._get_cache_key(f, "SELECT 1", "config_b")
        assert key1 != key2
