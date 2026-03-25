# tests/unit/test_cache.py
"""Unit tests for the cache manager."""

from pathlib import Path

import pytest

from slowql.core.cache import CacheManager
from slowql.core.models import AnalysisResult, Location, Query


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / ".slowql_cache"


@pytest.fixture
def cache_manager(cache_dir: Path) -> CacheManager:
    return CacheManager(cache_dir=cache_dir)


def test_cache_init(cache_dir: Path) -> None:
    """Test that initializing cache creates the directory and gitignore."""
    assert not cache_dir.exists()
    CacheManager(cache_dir=cache_dir)
    assert cache_dir.exists()
    assert (cache_dir / ".gitignore").exists()


def test_cache_set_and_get(cache_manager: CacheManager, cache_dir: Path) -> None:
    """Test storing and retrieving an analysis result."""
    file_path = Path("test.sql")
    content = "SELECT 1;"
    config_hash = "fake_hash_123"

    # Create dummy result
    query = Query(
        raw=content,
        normalized=content,
        dialect="universal",
        location=Location(1, 1),
    )
    # Put a fake ast to test scrubbing
    query.ast = "some_complex_ast_object"

    result = AnalysisResult(
        dialect="universal",
        config_hash=config_hash,
        queries=[query]
    )

    # Set cache
    cache_manager.set(file_path, content, config_hash, result)

    # Check cache file was created
    cache_files = list(cache_dir.glob("*.cache"))
    assert len(cache_files) == 1

    # Get cache
    cached_result = cache_manager.get(file_path, content, config_hash)
    assert cached_result is not None
    assert cached_result.dialect == "universal"
    assert cached_result.config_hash == config_hash
    assert len(cached_result.queries) == 1

    # Ensure ast was preserved during caching (required for cross-file analysis)
    assert cached_result.queries[0].ast == "some_complex_ast_object"


def test_cache_get_miss(cache_manager: CacheManager) -> None:
    """Test cache miss scenarios."""
    file_path = Path("test.sql")
    content = "SELECT 1;"
    config_hash = "fake_hash_123"

    # Should return None if not cached
    assert cache_manager.get(file_path, content, config_hash) is None

    # Set cache
    result = AnalysisResult()
    cache_manager.set(file_path, content, config_hash, result)

    # Miss due to different content
    assert cache_manager.get(file_path, "SELECT 2;", config_hash) is None

    # Miss due to different config hash
    assert cache_manager.get(file_path, content, "different_hash") is None

    # Miss due to different file path
    assert cache_manager.get(Path("other.sql"), content, config_hash) is None


def test_cache_clear(cache_manager: CacheManager, cache_dir: Path) -> None:
    """Test clearing the cache."""
    cache_manager.set(Path("f1.sql"), "A", "hash", AnalysisResult())
    cache_manager.set(Path("f2.sql"), "B", "hash", AnalysisResult())

    assert len(list(cache_dir.glob("*.cache"))) == 2

    cache_manager.clear()

    assert len(list(cache_dir.glob("*.cache"))) == 0
    # .gitignore should still be there
    assert (cache_dir / ".gitignore").exists()
