from __future__ import annotations

import logging
from typing import Any

from slowql.core.models import Issue, Severity

logger = logging.getLogger(__name__)

try:
    from lsprotocol.types import Diagnostic, DiagnosticSeverity, Position, Range
    from pygls.server import LanguageServer  # type: ignore[attr-defined]

    HAS_PYGLS = True
except ImportError:
    HAS_PYGLS = False

    class LanguageServer:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "The pygls library is required to use the Language Server features. "
                "Install it with: pip install slowql[lsp]"
            )

    # Dummy classes to make mypy happy when pygls is missing
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


def map_severity(severity: Severity) -> int:
    """Map SlowQL Severity to LSP DiagnosticSeverity."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return int(DiagnosticSeverity.Error)
    if severity == Severity.MEDIUM:
        return int(DiagnosticSeverity.Warning)
    if severity == Severity.LOW:
        return int(DiagnosticSeverity.Information)
    return int(DiagnosticSeverity.Hint)


def issue_to_diagnostic(issue: Issue) -> Diagnostic:
    """Convert a SlowQL Issue into an LSP Diagnostic."""
    # Note: LSP lines and characters are 0-indexed, SlowQL is 1-indexed.
    start_line = (issue.location.line - 1) if issue.location and issue.location.line else 0
    start_col = (issue.location.column - 1) if issue.location and issue.location.column else 0

    return Diagnostic(
        range=Range(
            start=Position(line=start_line, character=start_col),
            end=Position(line=start_line, character=start_col + 1),  # Minimum 1 character length
        ),
        message=issue.message,
        severity=map_severity(issue.severity),  # type: ignore[arg-type]
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
