from __future__ import annotations

import logging
from typing import Any

from slowql.core.models import Issue, Severity

logger = logging.getLogger(__name__)

try:
    from lsprotocol.types import (
        TEXT_DOCUMENT_DID_CHANGE,
        TEXT_DOCUMENT_DID_OPEN,
        TEXT_DOCUMENT_DID_SAVE,
        Diagnostic,
        DiagnosticSeverity,
        DidChangeTextDocumentParams,
        DidOpenTextDocumentParams,
        DidSaveTextDocumentParams,
        Position,
        PublishDiagnosticsParams,
        Range,
    )
    from pygls.lsp.server import LanguageServer

    HAS_PYGLS = True
except ImportError:
    HAS_PYGLS = False

    class LanguageServer:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "The pygls library is required to use the Language Server features. "
                "Install it with: pip install slowql[lsp]"
            )

    # Dummy classes so helpers work without pygls installed
    class DiagnosticSeverity:  # type: ignore[no-redef]
        Error = 1
        Warning = 2
        Information = 3
        Hint = 4

    class Position:  # type: ignore[no-redef]
        def __init__(self, line: int, character: int) -> None:
            self.line = line
            self.character = character

    class Range:  # type: ignore[no-redef]
        def __init__(self, start: Position, end: Position) -> None:
            self.start = start
            self.end = end

    class Diagnostic:  # type: ignore[no-redef]
        def __init__(
            self,
            range: Range,
            message: str,
            severity: int | None = None,
            source: str | None = None,
            code: str | None = None,
        ) -> None:
            self.range = range
            self.message = message
            self.severity = severity
            self.source = source
            self.code = code


# ---------------------------------------------------------------------------
# Helpers - always importable (no pygls required)
# ---------------------------------------------------------------------------


def map_severity(severity: Severity) -> DiagnosticSeverity:
    """Map SlowQL Severity to LSP DiagnosticSeverity."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return DiagnosticSeverity.Error
    if severity == Severity.MEDIUM:
        return DiagnosticSeverity.Warning
    if severity == Severity.LOW:
        return DiagnosticSeverity.Information
    return DiagnosticSeverity.Hint


def issue_to_diagnostic(issue: Issue) -> Diagnostic:
    """Convert a SlowQL Issue into an LSP Diagnostic."""
    start_line = (issue.location.line - 1) if issue.location and issue.location.line else 0
    start_col = (issue.location.column - 1) if issue.location and issue.location.column else 0

    return Diagnostic(
        range=Range(
            start=Position(line=start_line, character=start_col),
            end=Position(line=start_line, character=start_col + 1),
        ),
        message=issue.message,
        severity=map_severity(issue.severity),
        code=issue.rule_id,
        source="SlowQL",
    )


class SlowQLLanguageServer(LanguageServer):
    """
    A minimal Language Server for SlowQL.
    Provides diagnostic reporting for SQL files.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if not HAS_PYGLS:
            raise ImportError(
                "The pygls library is required to use the Language Server features. "
                "Install it with: pip install slowql[lsp]"
            )
        super().__init__(*args, **kwargs)
        self.logger = logger


# ---------------------------------------------------------------------------
# Diagnostics helper
# ---------------------------------------------------------------------------


def _validate_document(server: SlowQLLanguageServer, uri: str, source: str) -> None:
    """Run SlowQL analysis on *source* and publish diagnostics for *uri*."""
    from slowql.core.engine import SlowQL  # noqa: PLC0415

    try:
        engine = SlowQL()
        result = engine.analyze(source, file_path=uri)
        diagnostics = [issue_to_diagnostic(issue) for issue in result.issues]
    except Exception:
        server.logger.exception("SlowQL analysis failed for %s", uri)
        diagnostics = []

    server.text_document_publish_diagnostics(
        PublishDiagnosticsParams(uri=uri, diagnostics=diagnostics)
    )


# ---------------------------------------------------------------------------
# Factory — build a fully-wired server instance (requires pygls)
# ---------------------------------------------------------------------------


def create_server() -> SlowQLLanguageServer:
    """Create and return a SlowQLLanguageServer with diagnostics handlers."""
    srv = SlowQLLanguageServer("slowql-lsp", "v0.0.1")

    @srv.feature(TEXT_DOCUMENT_DID_OPEN)
    def did_open(ls: SlowQLLanguageServer, params: DidOpenTextDocumentParams) -> None:
        """Analyse a document when it is first opened."""
        _validate_document(ls, params.text_document.uri, params.text_document.text)

    @srv.feature(TEXT_DOCUMENT_DID_CHANGE)
    def did_change(ls: SlowQLLanguageServer, params: DidChangeTextDocumentParams) -> None:
        """Re-analyse a document whenever its content changes."""
        text = params.content_changes[-1].text
        _validate_document(ls, params.text_document.uri, text)

    @srv.feature(TEXT_DOCUMENT_DID_SAVE)
    def did_save(ls: SlowQLLanguageServer, params: DidSaveTextDocumentParams) -> None:
        """Re-analyse on save (if the client sends the text)."""
        if params.text is not None:
            _validate_document(ls, params.text_document.uri, params.text)

    return srv


def main() -> None:
    """Entry-point: create the server and start it in stdio mode."""
    srv = create_server()
    srv.start_io()


# ---------------------------------------------------------------------------
# python -m slowql.lsp.server
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
