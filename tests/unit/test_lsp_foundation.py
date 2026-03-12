from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from slowql.core.models import Issue, Location, Severity
from slowql.lsp.server import HAS_PYGLS, issue_to_diagnostic, map_severity

if HAS_PYGLS:
    from lsprotocol.types import DiagnosticSeverity
else:
    class DiagnosticSeverity:
        Error = 1
        Warning = 2
        Information = 3
        Hint = 4

def test_severity_mapping():
    """Test mapping SlowQL Severity to LSP DiagnosticSeverity."""
    assert map_severity(Severity.CRITICAL) == DiagnosticSeverity.Error
    assert map_severity(Severity.HIGH) == DiagnosticSeverity.Error
    assert map_severity(Severity.MEDIUM) == DiagnosticSeverity.Warning
    assert map_severity(Severity.LOW) == DiagnosticSeverity.Information
    assert map_severity(Severity.INFO) == DiagnosticSeverity.Hint


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

    diagnostic = issue_to_diagnostic(issue)

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


def test_graceful_failure_without_pygls():
    """Test that SlowQLLanguageServer fails gracefully when pygls is absent."""
    with patch.dict(sys.modules, {"pygls": None, "lsprotocol": None}), patch("slowql.lsp.server.HAS_PYGLS", False):
        from slowql.lsp.server import SlowQLLanguageServer
        with pytest.raises(ImportError, match="pygls library is required"):
                SlowQLLanguageServer()
