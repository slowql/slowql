# slowql/src/slowql/core/cache.py
"""
Caching mechanism for SlowQL analysis results.
Enables incremental analysis by skipping files that haven't changed.
"""

from __future__ import annotations

import hashlib
import pickle
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from slowql.core.models import AnalysisResult

# Fallback version if it can't be imported
try:
    from slowql import __version__ as slowql_version
except ImportError:
    slowql_version = "unknown"

class CacheManager:
    """Manages caching of AnalysisResult objects."""

    def __init__(self, cache_dir: Path | str = ".slowql_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # Prevent cache files from being committed by default
        gitignore_path = self.cache_dir / ".gitignore"
        if not gitignore_path.exists():
            try:
                gitignore_path.write_text("*\n", encoding="utf-8")
            except OSError:
                pass

    def _get_cache_key(self, file_path: Path, content: str, config_hash: str) -> str:
        """
        Compute a unique cache key based on file content, absolute path,
        SlowQL version, and config hash.
        """
        hasher = hashlib.sha256()
        hasher.update(str(file_path.resolve()).encode("utf-8"))
        hasher.update(content.encode("utf-8"))
        hasher.update(config_hash.encode("utf-8"))
        hasher.update(str(slowql_version).encode("utf-8"))
        return hasher.hexdigest()

    def get(self, file_path: Path, content: str, config_hash: str) -> AnalysisResult | None:
        """
        Retrieve cached AnalysisResult for a file if it exists and is valid.
        """
        key = self._get_cache_key(file_path, content, config_hash)
        cache_file = self.cache_dir / f"{key}.cache"

        if not cache_file.exists():
            return None

        try:
            with cache_file.open("rb") as f:
                return pickle.load(f)
        except Exception:
            # If cache is corrupted or incompatible, ignore it
            return None

    def set(self, file_path: Path, content: str, config_hash: str, result: AnalysisResult) -> None:
        """
        Store AnalysisResult in the cache.
        """
        key = self._get_cache_key(file_path, content, config_hash)
        cache_file = self.cache_dir / f"{key}.cache"

        # Scrub AST to save space and avoid pickle issues
        # BUT: Do not mutate the original result object in-place!
        # For now, we keep the AST to support cross-file analysis on cached results.
        # If we want to save space, we should deepcopy the result first.

        try:
            with cache_file.open("wb") as f:
                pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass  # Fail silently if cache cannot be written to

    def clear(self) -> None:
        """Clear all cached entries."""
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                cache_file.unlink()
            except Exception:
                pass
