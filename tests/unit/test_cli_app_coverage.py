import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Mock readchar before importing app to avoid ImportError details
# We create a mock object that mimics the structure of the readchar library
mock_readchar = MagicMock()
mock_readchar.key.UP = "UP_KEY"
mock_readchar.key.DOWN = "DOWN_KEY"
mock_readchar.key.ENTER = "ENTER_KEY"
mock_readchar.key.CTRL_C = "CTRL_C_KEY"

sys.modules["readchar"] = mock_readchar
sys.modules["readchar.key"] = mock_readchar.key

from slowql.cli.app import (  # noqa: E402
    QueryCache,
    SessionManager,
    _run_exports,
    compare_mode,
    ensure_reports_dir,
    export_interactive,
    init_cli,
    run_analysis_loop,
    safe_path,
    show_quick_actions_menu,
)
from slowql.core.models import Severity  # noqa: E402


def _create_input_side_effect(values, exhaust_action="eof"):
    """
    Create a side_effect callable for mocking input().
    Prevents infinite loops by raising EOFError or returning empty strings
    when values are exhausted, with a hard safety limit.
    """
    iterator = iter(values)
    call_count = [0]
    max_calls = len(values) + 100  # Safety limit

    def side_effect(*_args, **_kwargs):
        call_count[0] += 1
        if call_count[0] > max_calls:
            raise RuntimeError(f"Input called {call_count[0]} times - possible infinite loop!")
        try:
            return next(iterator)
        except StopIteration as e:
            if exhaust_action == "eof":
                raise EOFError("End of mock input") from e
            elif exhaust_action == "empty":
                return ""
            raise e

    return side_effect


def _create_readkey_side_effect(values, default=mock_readchar.key.ENTER):
    """
    Create a side_effect callable for mocking readchar.readkey().
    Prevents infinite loops by defaulting to ENTER or raising RuntimeError.
    """
    iterator = iter(values)
    call_count = [0]
    max_calls = len(values) + 50

    def side_effect(*_args, **_kwargs):
        call_count[0] += 1
        if call_count[0] > max_calls:
            raise RuntimeError(f"readkey called {call_count[0]} times - possible infinite loop!")
        try:
            return next(iterator)
        except StopIteration:
            return default

    return side_effect


@pytest.fixture
def mock_console():
    with patch("slowql.cli.app.console") as mock:
        yield mock


@pytest.fixture(autouse=True)
def mock_ui_components():
    """
    Globally mock all UI components that might start threads or block.
    We patch time.sleep globally here to avoid AttributeErrors if modules
    import it differently.
    """
    with (
        patch("slowql.cli.app.Progress") as m_prog,
        patch("slowql.cli.app.Live") as m_live_app,
        patch("slowql.cli.ui.animations.Live") as m_live_anim,
        patch("time.sleep", return_value=None),
    ):  # Patch global time.sleep
        m_prog.return_value.__enter__.return_value = MagicMock()
        m_live_app.return_value.__enter__.return_value = MagicMock()
        m_live_anim.return_value.__enter__.return_value = MagicMock()
        yield


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
        Severity.INFO: 0,
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
        # Mock session start to check formatting
        sm.session_start = datetime.now()
        assert "s" in sm.get_session_duration()


class TestCompareMode:
    def test_compare_mode_success(self, mock_console):
        mock_engine = MagicMock()
        result = MagicMock()
        result.issues = []
        mock_engine.analyze.return_value = result

        # compare_mode reads lines until TWO consecutive empty lines for each query
        inputs = [
            "SELECT 1",
            "",
            "",  # First query + 2 empty lines
            "SELECT 2",
            "",
            "",  # Second query + 2 empty lines
        ]

        # Use callable side_effect to properly raise EOFError at end
        with patch(
            "builtins.input", side_effect=_create_input_side_effect(inputs, exhaust_action="eof")
        ):
            compare_mode(mock_engine)

        assert mock_engine.analyze.call_count == 2
        assert mock_console.print.call_count >= 1

    def test_compare_mode_empty_queries(self, mock_console):  # noqa: ARG002
        mock_engine = MagicMock()
        inputs = ["", ""]  # Empty query input (just two empty lines)

        with patch(
            "builtins.input", side_effect=_create_input_side_effect(inputs, exhaust_action="eof")
        ):
            compare_mode(mock_engine)

        mock_engine.analyze.assert_not_called()

    def test_compare_mode_eof(self):
        mock_engine = MagicMock()

        def raise_eof(*_args, **_kwargs):
            raise EOFError

        with patch("builtins.input", side_effect=raise_eof):
            compare_mode(mock_engine)

        mock_engine.analyze.assert_not_called()


class TestQuickActions:
    def test_menu_interactive_flow(self, mock_analysis_result, tmp_path):
        # Select "Continue" (index 1) -> "2"
        with patch("slowql.cli.app.Prompt.ask", return_value="2"):
            assert (
                show_quick_actions_menu(mock_analysis_result, MagicMock(), tmp_path) is True
            )

    def test_menu_exit(self, mock_analysis_result, tmp_path):
        # Select "Exit" -> "3"
        with patch("slowql.cli.app.Prompt.ask", return_value="3"):
            assert (
                show_quick_actions_menu(mock_analysis_result, MagicMock(), tmp_path)
                is False
            )


class TestExportInteractive:
    def test_export_interactive_flow(self, mock_analysis_result, tmp_path):
        # Select JSON (default) -> "1"
        with patch("slowql.cli.app.Prompt.ask", return_value="1"), \
             patch("slowql.cli.app._run_exports") as mock_run:
            export_interactive(mock_analysis_result, tmp_path)
            mock_run.assert_called_with(mock_analysis_result, ["json"], tmp_path)


class TestAnalysisLoop:
    def test_loop_exception_handling(self, mock_console):
        with (
            patch("slowql.cli.app.SlowQL") as MockEngine,
            patch("slowql.cli.app.Config") as MockConfig,
            patch("slowql.cli.app.ConsoleReporter"),
            patch("slowql.cli.app.CyberpunkSQLEditor") as MockEditor,
        ):
            MockConfig.find_and_load.return_value = MagicMock()
            MockEngine.return_value.analyze.side_effect = Exception("TestCrash")

            # Editor returns one query then None to exit
            mock_editor_instance = MagicMock()
            mock_editor_instance.get_queries.side_effect = ["SELECT 1", None]
            MockEditor.return_value = mock_editor_instance

            # Don't continue after error
            with patch("slowql.cli.app.Confirm.ask", return_value=False):
                run_analysis_loop(mode="paste", intro_enabled=False, non_interactive=False)

            calls = [str(c) for c in mock_console.print.call_args_list]
            assert any("Error" in c or "error" in c.lower() for c in calls)


class TestExports:
    def test_run_exports_all(self, mock_analysis_result, tmp_path):
        with (
            patch("slowql.cli.app.JSONReporter") as m_json,
            patch("slowql.cli.app.HTMLReporter") as m_html,
            patch("slowql.cli.app.CSVReporter") as m_csv,
        ):
            _run_exports(mock_analysis_result, ["json", "html", "csv"], tmp_path)
            assert m_json.called
            assert m_html.called
            assert m_csv.called


class TestUtilityFunctions:
    def test_ensure_reports_dir(self, tmp_path):
        new_dir = tmp_path / "reports" / "subdir"
        result = ensure_reports_dir(new_dir)
        assert result.exists()
        assert result.is_dir()

    def test_safe_path_none(self):
        result = safe_path(None)
        assert result == Path.cwd() / "reports"

    def test_init_cli(self):
        with patch("slowql.cli.app.logger") as mock_logger:
            init_cli()
            mock_logger.info.assert_called_once_with("SlowQL CLI started")


class TestQueryCache:
    def test_cache_set_get(self):
        cache = QueryCache()
        result = MagicMock()
        cache.set("q", result)
        assert cache.get("q") == result

    def test_cache_miss(self):
        cache = QueryCache()
        assert cache.get("missing") is None
