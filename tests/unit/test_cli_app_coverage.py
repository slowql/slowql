
import pytest
from unittest.mock import MagicMock, patch, ANY
import sys
from pathlib import Path
from datetime import datetime

# Mock readchar before importing app to avoid ImportError details
sys.modules["readchar"] = MagicMock()
sys.modules["readchar.key"] = MagicMock()

from slowql.cli.app import (
    SessionManager, QueryCache, init_cli, ensure_reports_dir, safe_path,
    _run_exports, show_quick_actions_menu, export_interactive, compare_mode,
    run_analysis_loop, main
)
from slowql.core.models import Severity

# Fix for missing readchar attributes if they are used directly
import slowql.cli.app as app_module
if not hasattr(app_module, "readchar"):
     app_module.readchar = MagicMock()
     app_module.readchar.key.UP = "UP"
     app_module.readchar.key.DOWN = "DOWN"
     app_module.readchar.key.ENTER = "ENTER"

@pytest.fixture
def mock_console():
    with patch("slowql.cli.app.console") as mock:
        yield mock

@pytest.fixture(autouse=True)
def mock_rich_progress():
    with patch("slowql.cli.app.Progress") as mock:
        mock.return_value.__enter__.return_value = MagicMock()
        yield mock

@pytest.fixture(autouse=True)
def mock_live():
    with patch("slowql.cli.app.Live") as mock:
        mock.return_value.__enter__.return_value = MagicMock()
        yield mock

@pytest.fixture
def mock_analysis_result():
    result = MagicMock()
    result.queries = ["SELECT * FROM t"]
    issue = MagicMock()
    issue.to_dict.return_value = {"code": "TEST", "severity": "high"}
    issue.severity = Severity.HIGH
    issue.dimension = "performance"
    result.issues = [issue]
    result.statistics = MagicMock()
    result.statistics.by_severity = {
        Severity.HIGH: 1,
        Severity.CRITICAL: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0
    }
    return result

class TestSessionManager:
    def test_session_manager_flow(self, mock_analysis_result, tmp_path):
        sm = SessionManager()
        sm.add_analysis(mock_analysis_result)
        sm.display_summary()
        path = sm.export_session(tmp_path / "session.json")
        assert path.exists()
        
    def test_session_duration(self):
        sm = SessionManager()
        assert "s" in sm.get_session_duration()

class TestCompareMode:
    def test_compare_mode_success(self, mock_console):
        mock_engine = MagicMock()
        result = MagicMock()
        result.issues = []
        mock_engine.analyze.return_value = result
        
        # Test input flow:
        # Q1: "SELECT 1" -> "" (submit)
        # Q2: "SELECT 2" -> "" (submit)
        inputs = ["SELECT 1", "", "SELECT 2", ""]
        with patch("builtins.input", side_effect=inputs):
            compare_mode(mock_engine)
            
        assert mock_engine.analyze.call_count == 2
        assert mock_console.print.call_count >= 1

class TestQuickActions:
    def test_menu_interactive_flow(self, mock_analysis_result, tmp_path):
        # Force HAVE_READCHAR = True logic
        # Mock readchar.readkey to simulate: DOWN, ENTER (select second option: Report->HTML usually?)
        # Options: 0: Export JSON, 1: HTML, 2: CSV, ...
        # show_quick_actions_menu options: [Export, Compare, Continue, Exit]
        # 0: Export -> sub menu.
        # Let's try "Continue" (index 2).
        # Sequence: DOWN, DOWN, ENTER.
        
        with patch("slowql.cli.app.readchar") as mock_rc:
            mock_rc.readkey.side_effect = ["DOWN", "DOWN", "ENTER"]
            mock_rc.key.UP = "UP"
            mock_rc.key.DOWN = "DOWN"
            mock_rc.key.ENTER = "ENTER"
            
            # Should return True (Loop continues)
            assert show_quick_actions_menu(mock_analysis_result, MagicMock(), tmp_path) is True

    def test_menu_exit(self, mock_analysis_result, tmp_path):
        # Select Exit (index 3)
        with patch("slowql.cli.app.readchar") as mock_rc:
            mock_rc.readkey.side_effect = ["UP", "ENTER"] # UP wraps to last (Exit)
            mock_rc.key.UP = "UP"
            mock_rc.key.DOWN = "DOWN"
            mock_rc.key.ENTER = "ENTER"
            
            assert show_quick_actions_menu(mock_analysis_result, MagicMock(), tmp_path) is False

class TestExportInteractive:
    def test_export_interactive_flow(self, mock_analysis_result, tmp_path):
         # Select JSON (index 0) -> ENTER
         with patch("slowql.cli.app.readchar") as mock_rc:
            mock_rc.readkey.side_effect = ["ENTER"]
            mock_rc.key.UP = "UP"
            mock_rc.key.DOWN = "DOWN"
            mock_rc.key.ENTER = "ENTER"
            
            with patch("slowql.cli.app._run_exports") as mock_run:
                export_interactive(mock_analysis_result, tmp_path)
                mock_run.assert_called_with(mock_analysis_result, ["json"], tmp_path)

class TestAnalysisLoop:
    def test_loop_exception_handling(self, mock_console):
        with patch("slowql.cli.app.SlowQL") as MockEngine:
            MockEngine.return_value.analyze.side_effect = Exception("TestCrash")
            
            # Sequence: "SELECT 1" (submit implicit in paste mode linewise?), "exit"
            # run_analysis_loop(mode="paste") reads lines.
            # "SELECT 1" -> buffer. If line empty?
            # Paste mode accumulates lines until EOF or special token?
            # Actually paste mode reads `input()` repeatedly.
            # If line is empty, it analyzes.
            
            inputs = ["SELECT 1", "", "exit"]
            with patch("builtins.input", side_effect=inputs):
                with patch("slowql.cli.app.Confirm.ask", return_value=True):
                    run_analysis_loop(mode="paste", intro_enabled=False)

            calls = [str(c) for c in mock_console.print.call_args_list]
            assert any("Error" in c for c in calls)

class TestExports:
    def test_run_exports_all(self, mock_analysis_result, tmp_path):
        with patch("slowql.cli.app.JSONReporter") as m_json, \
             patch("slowql.cli.app.HTMLReporter") as m_html, \
             patch("slowql.cli.app.CSVReporter") as m_csv:
                 
            _run_exports(mock_analysis_result, ["json", "html", "csv"], tmp_path)
            assert m_json.called
            assert m_html.called
            assert m_csv.called
