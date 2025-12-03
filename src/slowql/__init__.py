from typing import Callable, Optional

__all__ = ["__version__"]

__version__: Optional[str] = None

# store only the `version` function (or None) to avoid mixing module and None types
version_func: Optional[Callable[[str], str]] = None
try:
    import importlib.metadata as _importlib_metadata
    version_func = _importlib_metadata.version
except Exception:
    version_func = None

if version_func is not None:
    try:
        __version__ = version_func("sqlguard")
    except Exception:
        try:
            __version__ = version_func("slowql")
        except Exception:
            __version__ = None
