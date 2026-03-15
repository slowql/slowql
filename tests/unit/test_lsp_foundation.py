from __future__ import annotations

import logging

import pytest

import slowql.core.engine as engine_module
from slowql.core.models import Issue, Location, Severity
from slowql.lsp import server as lsp_server

if lsp_server.HAS_PYGLS:
    from lsprotocol.types import DiagnosticSeverity
else:

    class DiagnosticSeverity:
        Error = 1
        Warning = 2
        Information = 3
        Hint = 4


def test_severity_mapping():
    """Test mapping SlowQL Severity to LSP DiagnosticSeverity."""
    assert lsp_server.map_severity(Severity.CRITICAL) == DiagnosticSeverity.Error
    assert lsp_server.map_severity(Severity.HIGH) == DiagnosticSeverity.Error
    assert lsp_server.map_severity(Severity.MEDIUM) == DiagnosticSeverity.Warning
    assert lsp_server.map_severity(Severity.LOW) == DiagnosticSeverity.Information
    assert lsp_server.map_severity(Severity.INFO) == DiagnosticSeverity.Hint


def test_issue_to_diagnostic():
    """Test converting a SlowQL Issue to an LSP Diagnostic."""
    issue = Issue(
        rule_id="TST-001",
        message="Test issue",
        severity=Severity.HIGH,
        dimension="quality",
        snippet="SELECT *",
        location=Location(
            line=10,
            column=5,
            end_line=10,
            end_column=15,
        ),
    )

    diagnostic = lsp_server.issue_to_diagnostic(issue)

    assert diagnostic.message == "Test issue"
    assert diagnostic.code == "TST-001"
    assert diagnostic.source == "SlowQL"
    assert diagnostic.severity == DiagnosticSeverity.Error

    # LSP locations are 0-indexed
    assert diagnostic.range.start.line == 9
    assert diagnostic.range.start.character == 4
    assert diagnostic.range.end.line == 9
    # Right now our basic diagnostics just add 1 column
    assert diagnostic.range.end.character == 5


def test_language_server_fallback_raises_import_error(monkeypatch):
    """Test that SlowQLLanguageServer raises ImportError when HAS_PYGLS is False."""
    monkeypatch.setattr(lsp_server, "HAS_PYGLS", False)

    with pytest.raises(ImportError, match="pygls library is required"):
        lsp_server.SlowQLLanguageServer()


def test_validate_document_publishes_diagnostics(monkeypatch):
    """Test _validate_document publishes diagnostics correctly."""

    class FakeServer:
        def __init__(self):
            self.published = None
            self.logger = logging.getLogger("fake_server")

        def text_document_publish_diagnostics(self, params):
            self.published = params

    fake_server = FakeServer()
    uri = "file:///test.sql"
    source = "SELECT * FROM users"

    class FakeResult:
        def __init__(self):
            self.issues = [
                Issue(
                    rule_id="RL-001",
                    message="Test issue",
                    severity=Severity.HIGH,
                    dimension="quality",
                    snippet="SELECT",
                    location=Location(line=1, column=1),
                )
            ]

    monkeypatch.setattr(engine_module.SlowQL, "analyze", lambda *_args, **_kwargs: FakeResult())

    lsp_server._validate_document(fake_server, uri, source)  # type: ignore[arg-type]

    assert fake_server.published is not None
    assert fake_server.published.uri == uri
    assert len(fake_server.published.diagnostics) == 1
    assert fake_server.published.diagnostics[0].message == "Test issue"


def test_validate_document_on_engine_failure_publishes_empty_diagnostics(monkeypatch):
    """Test _validate_document handles engine failure by publishing empty diagnostics."""

    class FakeServer:
        def __init__(self):
            self.published = None
            self.logger = logging.getLogger("fake_server")

        def text_document_publish_diagnostics(self, params):
            self.published = params

    fake_server = FakeServer()

    def raise_err(*_args, **_kwargs):
        raise RuntimeError("Engine crash")

    monkeypatch.setattr(engine_module.SlowQL, "analyze", raise_err)

    lsp_server._validate_document(fake_server, "file:///test.sql", "SELECT 1")  # type: ignore[arg-type]

    assert fake_server.published is not None
    assert len(fake_server.published.diagnostics) == 0


def test_create_server_registers_handlers(monkeypatch):
    """Test create_server registers required feature handlers."""
    features = {}

    class FakeServer:
        def __init__(self, *_args, **_kwargs):
            pass

        def feature(self, feature_name):
            def decorator(f):
                features[feature_name] = f
                return f

            return decorator

    monkeypatch.setattr(lsp_server, "SlowQLLanguageServer", FakeServer)

    lsp_server.create_server()

    assert lsp_server.TEXT_DOCUMENT_DID_OPEN in features
    assert lsp_server.TEXT_DOCUMENT_DID_CHANGE in features
    assert lsp_server.TEXT_DOCUMENT_DID_SAVE in features


def test_create_server_did_open_handler(monkeypatch):
    """Test the did_open handler calls _validate_document."""
    captured_handlers = {}

    class MockServer:
        def __init__(self, *_args, **_kwargs):
            pass

        def feature(self, name):
            def wrapper(f):
                captured_handlers[name] = f
                return f

            return wrapper

    monkeypatch.setattr(lsp_server, "SlowQLLanguageServer", MockServer)

    validated = []

    def fake_validate(_ls, uri, text):
        validated.append((uri, text))

    monkeypatch.setattr(lsp_server, "_validate_document", fake_validate)

    srv = lsp_server.create_server()

    class FakeDoc:
        def __init__(self):
            self.uri = "file:///test.sql"
            self.text = "SELECT 1"

    class FakeParams:
        def __init__(self):
            self.text_document = FakeDoc()

    handler = captured_handlers[lsp_server.TEXT_DOCUMENT_DID_OPEN]

    params = FakeParams()
    handler(srv, params)

    assert len(validated) == 1
    assert validated[0] == ("file:///test.sql", "SELECT 1")


def test_create_server_did_change_handler_uses_latest_change(monkeypatch):
    """Test did_change handler uses the last change in the list."""
    validated = []

    def fake_validate(_ls, uri, text):
        validated.append((uri, text))

    monkeypatch.setattr(lsp_server, "_validate_document", fake_validate)

    captured_handlers = {}

    class MockServer:
        def __init__(self, *_args, **_kwargs):
            pass

        def feature(self, name):
            def wrapper(f):
                captured_handlers[name] = f
                return f

            return wrapper

    monkeypatch.setattr(lsp_server, "SlowQLLanguageServer", MockServer)

    srv = lsp_server.create_server()
    handler = captured_handlers[lsp_server.TEXT_DOCUMENT_DID_CHANGE]

    class FakeDoc:
        def __init__(self):
            self.uri = "file:///test.sql"

    class FakeChange:
        def __init__(self, text):
            self.text = text

    class FakeParams:
        def __init__(self):
            self.text_document = FakeDoc()
            self.content_changes = [
                FakeChange("old"),
                FakeChange("new"),
            ]

    handler(srv, FakeParams())

    assert len(validated) == 1
    assert validated[0][1] == "new"


def test_create_server_did_save_handler_with_text(monkeypatch):
    """Test did_save handler calls validate if text is present."""
    validated = []

    def fake_validate(_ls, uri, text):
        validated.append((uri, text))

    monkeypatch.setattr(lsp_server, "_validate_document", fake_validate)

    captured_handlers = {}

    class MockServer:
        def __init__(self, *_args, **_kwargs):
            pass

        def feature(self, name):
            def wrapper(f):
                captured_handlers[name] = f
                return f

            return wrapper

    monkeypatch.setattr(lsp_server, "SlowQLLanguageServer", MockServer)

    srv = lsp_server.create_server()
    handler = captured_handlers[lsp_server.TEXT_DOCUMENT_DID_SAVE]

    class FakeDoc:
        def __init__(self):
            self.uri = "file:///test.sql"

    class FakeParams:
        def __init__(self):
            self.text_document = FakeDoc()
            self.text = "saved text"

    handler(srv, FakeParams())

    assert len(validated) == 1
    assert validated[0][1] == "saved text"


def test_create_server_did_save_handler_without_text(monkeypatch):
    """Test did_save handler does not call validate if text is None."""
    validated = []

    def fake_validate(_ls, uri, text):
        validated.append((uri, text))

    monkeypatch.setattr(lsp_server, "_validate_document", fake_validate)

    captured_handlers = {}

    class MockServer:
        def __init__(self, *_args, **_kwargs):
            pass

        def feature(self, name):
            def wrapper(f):
                captured_handlers[name] = f
                return f

            return wrapper

    monkeypatch.setattr(lsp_server, "SlowQLLanguageServer", MockServer)

    srv = lsp_server.create_server()
    handler = captured_handlers[lsp_server.TEXT_DOCUMENT_DID_SAVE]

    class FakeDoc:
        def __init__(self):
            self.uri = "file:///test.sql"

    class FakeParams:
        def __init__(self):
            self.text_document = FakeDoc()
            self.text = None

    handler(srv, FakeParams())

    assert len(validated) == 0


def test_main_starts_io(monkeypatch):
    """Test main() correctly starts the server."""
    started = False

    class FakeServer:
        def start_io(self):
            nonlocal started
            started = True

    monkeypatch.setattr(lsp_server, "create_server", lambda: FakeServer())

    lsp_server.main()
    assert started is True


def test_issue_to_diagnostic_no_location():
    """Test issue_to_diagnostic with no location."""
    issue = Issue(
        rule_id="TST-002",
        message="No location",
        severity=Severity.INFO,
        dimension="quality",
        snippet="",
        location=None,
    )
    diagnostic = lsp_server.issue_to_diagnostic(issue)
    assert diagnostic.range.start.line == 0
    assert diagnostic.range.start.character == 0


def test_issue_to_diagnostic_partial_location():
    """Test issue_to_diagnostic with line or column = 0."""
    # Test line=0
    issue_line_0 = Issue(
        rule_id="TST-003",
        message="Line 0",
        severity=Severity.INFO,
        dimension="quality",
        snippet="",
        location=Location(line=0, column=5),
    )
    diag_line_0 = lsp_server.issue_to_diagnostic(issue_line_0)
    assert diag_line_0.range.start.line == 0
    assert diag_line_0.range.start.character == 4

    # Test column=0
    issue_col_0 = Issue(
        rule_id="TST-004",
        message="Col 0",
        severity=Severity.INFO,
        dimension="quality",
        snippet="",
        location=Location(line=5, column=0),
    )
    diag_col_0 = lsp_server.issue_to_diagnostic(issue_col_0)
    assert diag_col_0.range.start.line == 4
    assert diag_col_0.range.start.character == 0


def test_fallback_language_server_init():
    """Test the fallback LanguageServer class raises ImportError on init."""
    # This only applies if pygls is not installed
    if not lsp_server.HAS_PYGLS:
        with pytest.raises(ImportError, match="pygls library is required"):
            lsp_server.LanguageServer()


def test_slowql_language_server_init_success(monkeypatch):
    """Test SlowQLLanguageServer init success branch by mocking HAS_PYGLS."""
    monkeypatch.setattr(lsp_server, "HAS_PYGLS", True)

    # If pygls is not installed, the base class is the dummy one that raises ImportError.
    # We patch its __init__ to allow instantiation for this test.
    if not hasattr(lsp_server.LanguageServer, "feature"):  # Dummy check
        monkeypatch.setattr(
            "slowql.lsp.server.LanguageServer.__init__", lambda *_, **__: None
        )

    ls = lsp_server.SlowQLLanguageServer("test", "v1")
    assert ls.logger is not None


def test_validate_document_error_handling_logs_exception(monkeypatch):
    """Test _validate_document logs the exception when analysis fails."""

    class FakeServer:
        def __init__(self):
            self.logger = logging.getLogger("test_logger")
            self.published = None

        def text_document_publish_diagnostics(self, params):
            self.published = params

    fake_server = FakeServer()

    def raise_err(*_, **__):
        raise ValueError("Boom")

    monkeypatch.setattr(engine_module.SlowQL, "analyze", raise_err)

    logs = []
    monkeypatch.setattr(
        fake_server.logger, "exception", lambda msg, *args: logs.append(msg % args)
    )

    lsp_server._validate_document(fake_server, "uri", "source")  # type: ignore[arg-type]

    assert "SlowQL analysis failed for uri" in logs[0]
    assert len(fake_server.published.diagnostics) == 0


def test_dummy_classes_instantiation():
    """Directly test dummy classes if pygls is missing."""
    if not lsp_server.HAS_PYGLS:
        pos = lsp_server.Position(line=1, character=2)
        assert pos.line == 1
        assert pos.character == 2

        rng = lsp_server.Range(start=pos, end=pos)
        assert rng.start == pos
        assert rng.end == pos

        diag = lsp_server.Diagnostic(
            range=rng, message="msg", severity=1, source="src", code="c"
        )
        assert diag.message == "msg"
        assert diag.severity == 1

        params = lsp_server.PublishDiagnosticsParams(uri="uri", diagnostics=[diag])
        assert params.uri == "uri"
        assert params.diagnostics == [diag]
