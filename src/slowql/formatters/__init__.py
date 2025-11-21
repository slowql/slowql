
try:
    from importlib.metadata import version as _get_version
except Exception:
    _get_version = None

__version__ = None
if _get_version:
    try:
        __version__ = _get_version("slowql")
    except Exception:
        __version__ = None

# slowql.formatters package
__all__ = ["console"]
