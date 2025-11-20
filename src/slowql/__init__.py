# create/overwrite src/slowql/__init__.py with importlib.metadata approach
cat > src/slowql/__init__.py <<'PY'
# slowql package initializer
try:
    from importlib.metadata import version as _get_version
except Exception:
    try:
        # Python < 3.8 fallback (shouldn't be needed on modern Python)
        from importlib_metadata import version as _get_version
    except Exception:
        _get_version = None

__version__ = None
if _get_version:
    try:
        __version__ = _get_version("slowql")
    except Exception:
        __version__ = None