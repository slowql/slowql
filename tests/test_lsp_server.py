"""Coverage tests for LSP server."""
from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest

from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Severity
from slowql.lsp.server import (
    HAS_PYGLS,
    _validate_document,
    issue_to_diagnostic,
    main,
    map_severity,
)


@pytest.mark.skipif(not HAS_PYGLS, reason="pygls/lsprotocol not installed")
def test_map_severity():
    from lsprotocol.types import DiagnosticSeverity
    assert map_severity(Severity.CRITICAL) == DiagnosticSeverity.Error
    assert map_severity(Severity.HIGH) == DiagnosticSeverity.Error
    assert map_severity(Severity.MEDIUM) == DiagnosticSeverity.Warning
    assert map_severity(Severity.LOW) == DiagnosticSeverity.Information
    assert map_severity(Severity.INFO) == DiagnosticSeverity.Hint


@pytest.mark.skipif(not HAS_PYGLS, reason="pygls/lsprotocol not installed")
def test_issue_to_diagnostic():
    from lsprotocol.types import DiagnosticSeverity

    issue = Issue(
        rule_id="TEST-001",
        message="A test issue",
        severity=Severity.HIGH,
        dimension=Dimension.SECURITY,
        location=Location(line=5, column=10),
        snippet="SELECT 1",
    )
    diag = issue_to_diagnostic(issue)
    assert diag.message == "A test issue"
    assert diag.code == "TEST-001"
    assert diag.source == "SlowQL"
    assert diag.severity == DiagnosticSeverity.Error
    # LSP uses 0-based indexing
    assert diag.range.start.line == 4
    assert diag.range.start.character == 9
    assert diag.range.end.line == 4
    assert diag.range.end.character == 10


@pytest.mark.skipif(not HAS_PYGLS, reason="pygls/lsprotocol not installed")
def test_issue_to_diagnostic_no_location():
    """Fallback when location data is missing."""
    issue = Issue(
        rule_id="TEST-002",
        message="No location",
        severity=Severity.LOW,
        dimension=Dimension.QUALITY,
        location=Location(line=0, column=0),
        snippet="",
    )
    diag = issue_to_diagnostic(issue)
    assert diag.range.start.line == 0  # Falls back to 0
    assert diag.range.start.character == 0


@pytest.mark.skipif(not HAS_PYGLS, reason="pygls not installed")
class TestLspValidation:
    @patch("slowql.core.engine.SlowQL.analyze")
    def test_validate_document_success(self, mock_analyze):
        server = MagicMock()

        result = AnalysisResult()
        result.add_issue(Issue(
            rule_id="T-1", message="Test", severity=Severity.INFO,
            dimension=Dimension.QUALITY, location=Location(line=1, column=1), snippet=""
        ))
        mock_analyze.return_value = result

        _validate_document(server, "file:///test.sql", "SELECT 1", schema=None)

        server.text_document_publish_diagnostics.assert_called_once()
        params = server.text_document_publish_diagnostics.call_args[0][0]
        assert params.uri == "file:///test.sql"
        assert len(params.diagnostics) == 1

    @patch("slowql.core.engine.SlowQL.analyze")
    def test_validate_document_exception(self, mock_analyze):
        server = MagicMock()
        mock_analyze.side_effect = Exception("Parse failed")

        _validate_document(server, "file:///test.sql", "SELECT 1", schema=None)

        # Exception should be caught and logged
        server.logger.exception.assert_called_once()
        server.text_document_publish_diagnostics.assert_called_once()
        params = server.text_document_publish_diagnostics.call_args[0][0]
        assert len(params.diagnostics) == 0


@pytest.mark.skipif(not HAS_PYGLS, reason="pygls not installed")
class TestLspMain:
    @patch("slowql.lsp.server.create_server")
    @patch("argparse.ArgumentParser.parse_known_args")
    def test_main_no_args(self, mock_parse, mock_create):
        mock_parse.return_value = (argparse.Namespace(schema=None, db=None), [])
        server_mock = MagicMock()
        mock_create.return_value = server_mock

        main()

        mock_create.assert_called_once_with(schema=None)
        server_mock.start_io.assert_called_once()

    @patch("slowql.schema.inspector.SchemaInspector.from_ddl_file")
    @patch("slowql.lsp.server.create_server")
    @patch("argparse.ArgumentParser.parse_known_args")
    def test_main_with_schema(self, mock_parse, mock_create, mock_from_file):
        mock_parse.return_value = (argparse.Namespace(schema="schema.sql", db=None), [])
        schema_mock = MagicMock()
        schema_mock.tables = {"t": "test"}
        mock_from_file.return_value = schema_mock
        server_mock = MagicMock()
        mock_create.return_value = server_mock

        main()

        mock_create.assert_called_once_with(schema=schema_mock)

    @patch("slowql.schema.inspector.SchemaInspector.from_ddl_file")
    @patch("argparse.ArgumentParser.parse_known_args")
    def test_main_with_schema_error(self, mock_parse, mock_from_file):
        mock_parse.return_value = (argparse.Namespace(schema="schema.sql", db=None), [])
        mock_from_file.side_effect = Exception("File missing")

        with patch("slowql.lsp.server.logger") as mock_logger, patch("slowql.lsp.server.create_server") as mock_create:
            mock_create.return_value = MagicMock()
            main()
            mock_logger.warning.assert_called_once()
            mock_create.assert_called_once_with(schema=None)
