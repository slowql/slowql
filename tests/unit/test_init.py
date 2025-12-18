import importlib


def reload_slowql(monkeypatch, fake_version_func):
    # Patch importlib.metadata.version
    monkeypatch.setattr("importlib.metadata.version", fake_version_func)
    # Reload module to re-execute __init__.py
    if "slowql" in importlib.sys.modules:
        del importlib.sys.modules["slowql"]
    import slowql  # noqa: PLC0415 - a local import is needed to re-execute __init__.py

    return slowql


def test_version_sqlguard(monkeypatch):
    def fake_version(name):
        if name == "sqlguard":
            return "1.2.3"
        raise Exception("not found")

    slowql = reload_slowql(monkeypatch, fake_version)
    assert slowql.__version__ == "1.2.3"


def test_version_slowql(monkeypatch):
    def fake_version(name):
        if name == "slowql":
            return "4.5.6"
        raise Exception("not found")

    slowql = reload_slowql(monkeypatch, fake_version)
    assert slowql.__version__ == "4.5.6"


def test_version_none(monkeypatch):
    def fake_version(_name):
        raise Exception("fail")

    slowql = reload_slowql(monkeypatch, fake_version)
    assert slowql.__version__ is None


def test_importlib_metadata_missing(monkeypatch):
    # Simulate importlib.metadata not available
    monkeypatch.setitem(importlib.sys.modules, "importlib.metadata", None)
    if "slowql" in importlib.sys.modules:
        del importlib.sys.modules["slowql"]
    import slowql  # noqa: PLC0415 - a local import is needed to re-execute __init__.py

    assert slowql.__version__ is None
