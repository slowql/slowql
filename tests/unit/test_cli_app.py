"""Tests for CLI app functionality."""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

from slowql.cli.app import (
    QueryCache,
    SessionManager,
    _run_exports,
    build_argparser,
    compare_mode,
    ensure_reports_dir,
    export_interactive,
    init_cli,
    main,
    run_analysis_loop,
    safe_path,
    show_quick_actions_menu,
)
from slowql.core.models import AnalysisResult, Dimension, Issue, Location, Query, Severity


class TestSessionManager:
    """Test SessionManager class."""

    def test_init(self):
        """Test SessionManager initialization."""
        session = SessionManager()
        assert session.queries_analyzed == 0
        assert session.total_issues == 0
        assert isinstance(session.history, list)
        assert session.history == []
        assert session.severity_breakdown == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def test_add_analysis(self):
        """Test adding analysis results."""
        session = SessionManager()

        # Create mock result

        issues = [
            Issue(
                rule_id="TEST-001",
                message="Test issue",
                severity=Severity.HIGH,
                dimension=Dimension.SECURITY,
                location=Location(line=1, column=1, file="test.sql"),
                snippet="SELECT * FROM test",
            )
        ]
        queries = [
            Query(
                raw="SELECT * FROM test",
                normalized="SELECT * FROM test",
                dialect="generic",
                location=Location(line=1, column=1, file="test.sql"),
            )
        ]
        result = AnalysisResult(
            queries=queries,
            issues=issues,
            statistics=MagicMock(by_severity={Severity.HIGH: 1}),
        )

        session.add_analysis(result)

        assert session.queries_analyzed == 1
        assert session.total_issues == 1
        assert session.severity_breakdown["high"] == 1
        assert len(session.history) == 1
        assert session.history[0]["queries"] == 1
        assert session.history[0]["issues"] == 1

    def test_get_session_duration(self):
        """Test session duration calculation."""
        session = SessionManager()
        # Mock session start to be 1 hour ago
        session.session_start = datetime.now() - timedelta(hours=1, minutes=30, seconds=45)

        duration = session.get_session_duration()
        assert "1h 30m 45s" in duration

    def test_get_session_duration_minutes_only(self):
        """Test session duration with minutes only."""
        session = SessionManager()
        # Mock session start to be 30 minutes ago
        session.session_start = datetime.now() - timedelta(minutes=30, seconds=45)

        duration = session.get_session_duration()
        assert "30m 45s" in duration

    def test_get_session_duration_seconds_only(self):
        """Test session duration with seconds only."""
        session = SessionManager()
        # Mock session start to be 45 seconds ago
        session.session_start = datetime.now() - timedelta(seconds=45)

        duration = session.get_session_duration()
        assert "45s" in duration

    def test_display_summary(self):
        """Test session summary display."""
        session = SessionManager()
        with patch("slowql.cli.app.console") as mock_console:
            session.display_summary()
            mock_console.print.assert_called_once()

    def test_export_session(self):
        """Test session export."""
        session = SessionManager()

        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = session.export_session(Path(temp_dir) / "test_session.json")

            assert export_path.exists()
            with export_path.open() as f:
                data = json.load(f)
                assert "session_start" in data
                assert "session_end" in data
                assert "duration" in data
                assert "queries_analyzed" in data
                assert "total_issues" in data
                assert "severity_breakdown" in data
                assert "history" in data


class TestQueryCache:
    """Test QueryCache class."""

    def test_init(self):
        """Test QueryCache initialization."""
        cache = QueryCache()
        assert cache.cache == {}

    def test_get_set(self):
        """Test cache get and set operations."""
        cache = QueryCache()
        result = MagicMock()

        # Test set and get
        cache.set("SELECT * FROM test", result)
        retrieved = cache.get("SELECT * FROM test")
        assert retrieved == result

        # Test case insensitive and whitespace normalized
        retrieved2 = cache.get("  select   *   from   test  ")
        assert retrieved2 == result

    def test_get_nonexistent(self):
        """Test getting nonexistent cache entry."""
        cache = QueryCache()
        assert cache.get("nonexistent") is None

    def test_clear(self):
        """Test cache clearing."""
        cache = QueryCache()
        cache.set("test", MagicMock())
        assert len(cache.cache) == 1

        cache.clear()
        assert len(cache.cache) == 0


class TestUtilityFunctions:
    """Test utility functions."""

    def test_ensure_reports_dir(self):
        """Test ensure_reports_dir function."""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "reports" / "subdir"
            result = ensure_reports_dir(path)
            assert result.exists()
            assert result.is_dir()
            assert result == path

    def test_safe_path(self):
        """Test safe_path function."""
        # Test with None
        result = safe_path(None)
        assert result == Path.cwd() / "reports"

        # Test with path
        test_path = Path("/tmp/test")
        result = safe_path(test_path)
        assert result == test_path.resolve()

    @patch("slowql.cli.app.logger")
    def test_init_cli(self, mock_logger):
        """Test init_cli function."""
        init_cli()
        mock_logger.info.assert_called_once_with("SlowQL CLI started")


class TestExportFunctions:
    """Test export-related functions."""

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.ensure_reports_dir")
    @patch("slowql.cli.app.safe_path")
    def test_run_exports(self, mock_safe_path, mock_ensure_reports_dir, mock_console):
        """Test _run_exports function."""
        mock_safe_path.return_value = Path("/tmp/reports")
        mock_ensure_reports_dir.return_value = Path("/tmp/reports")

        result = MagicMock()

        with patch("pathlib.Path.open", mock_open()) as mock_file:
            _run_exports(result, ["json", "html", "csv"], Path("/tmp/reports"))

            # Should open 3 files
            assert mock_file.call_count == 3
            # Should print 3 success messages
            assert mock_console.print.call_count == 3

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.ensure_reports_dir")
    @patch("slowql.cli.app.safe_path")
    def test_run_exports_with_error(self, mock_safe_path, mock_ensure_reports_dir, mock_console):
        """Test _run_exports with export error."""
        mock_safe_path.return_value = Path("/tmp/reports")
        mock_ensure_reports_dir.return_value = Path("/tmp/reports")

        result = MagicMock()

        with patch("pathlib.Path.open", side_effect=Exception("Test error")):
            _run_exports(result, ["json"], Path("/tmp/reports"))

            # Should print error message
            mock_console.print.assert_called_once()
            args = mock_console.print.call_args[0][0]
            assert "Failed to export json" in args

    @patch("slowql.cli.app.export_interactive")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_show_quick_actions_menu_export_fallback(
        self, mock_prompt, _mock_console, mock_export
    ):
        """Test show_quick_actions_menu fallback with export selection."""
        # Mock Prompt.ask to return "1" (export option)
        mock_prompt.ask.return_value = "1"

        result = MagicMock()
        out_dir = Path("/tmp")

        # Test export selection with fallback by mocking readchar import to fail
        with patch.dict("sys.modules", {"readchar": None}):
            continue_analysis = show_quick_actions_menu(result, None, out_dir)

            mock_export.assert_called_once_with(result, out_dir)
            assert continue_analysis is True

    @patch("slowql.cli.app.export_interactive")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_show_quick_actions_menu_no_readchar_fallback(
        self, mock_prompt, _mock_console, mock_export
    ):
        """Test show_quick_actions_menu when readchar import fails."""
        # Mock Prompt.ask to return "2" (continue option)
        mock_prompt.ask.return_value = "2"

        result = MagicMock()
        out_dir = Path("/tmp")

        # Test with readchar import failure
        with patch.dict("sys.modules", {"readchar": None}):
            continue_analysis = show_quick_actions_menu(result, None, out_dir)

            assert continue_analysis is True
            mock_export.assert_not_called()

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_show_quick_actions_menu_continue_fallback(
        self, mock_prompt, _mock_console
    ):
        """Test show_quick_actions_menu fallback with continue selection."""
        # Mock Prompt.ask to return "2" (continue option)
        mock_prompt.ask.return_value = "2"

        result = MagicMock()
        out_dir = Path("/tmp")

        with patch.dict("sys.modules", {"readchar": None}):
            continue_analysis = show_quick_actions_menu(result, None, out_dir)

            assert continue_analysis is True

    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_show_quick_actions_menu_exit_fallback(
        self, mock_prompt, _mock_console
    ):
        """Test show_quick_actions_menu fallback with exit selection."""
        # Mock Prompt.ask to return "3" (exit option)
        mock_prompt.ask.return_value = "3"

        result = MagicMock()
        out_dir = Path("/tmp")

        with patch.dict("sys.modules", {"readchar": None}):
            continue_analysis = show_quick_actions_menu(result, None, out_dir)

            assert continue_analysis is False

    @patch("slowql.cli.app._run_exports")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_export_interactive_json_fallback(
        self, mock_prompt, _mock_console, mock_run_exports
    ):
        """Test export_interactive fallback with JSON selection."""
        mock_prompt.ask.return_value = "1"

        result = MagicMock()
        out_dir = Path("/tmp")

        with patch.dict("sys.modules", {"readchar": None}):
            export_interactive(result, out_dir)

            mock_run_exports.assert_called_once_with(result, ["json"], out_dir)

    @patch("slowql.cli.app._run_exports")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Prompt")
    def test_export_interactive_all_fallback(
        self, mock_prompt, _mock_console, mock_run_exports
    ):
        """Test export_interactive fallback with All selection."""
        mock_prompt.ask.return_value = "4"

        result = MagicMock()
        out_dir = Path("/tmp")

        with patch.dict("sys.modules", {"readchar": None}):
            export_interactive(result, out_dir)

            mock_run_exports.assert_called_once_with(result, ["json", "html", "csv"], out_dir)


class TestCompareMode:
    """Test compare_mode function."""

    @patch("builtins.input")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Progress")
    def test_compare_mode_success(self, _mock_progress, mock_console, mock_input):
        """Test successful query comparison."""
        # Mock input for two queries (each followed by two empty lines to finish)
        # Added EOFError to ensure the loop terminates
        mock_input.side_effect = [
            "SELECT * FROM test1",
            "",
            "",
            "SELECT * FROM test2",
            "",
            "",
            EOFError(),
        ]

        engine = MagicMock()
        result1 = MagicMock()
        result1.issues = [MagicMock()]
        result2 = MagicMock()
        result2.issues = []
        engine.analyze.side_effect = [result1, result2]

        compare_mode(engine)

        # Should analyze both queries
        assert engine.analyze.call_count == 2
        # Should print comparison table
        assert mock_console.print.call_count >= 2

    @patch("builtins.input")
    @patch("slowql.cli.app.console")
    def test_compare_mode_empty_queries(self, mock_console, mock_input):
        """Test compare mode with empty queries."""
        # Added EOFError to ensure the loop terminates
        mock_input.side_effect = ["", "", "", "", EOFError()]

        engine = MagicMock()
        compare_mode(engine)

        # Should not analyze anything
        engine.analyze.assert_not_called()
        # Should print error message - console.print is called multiple times for the prompts
        assert mock_console.print.call_count >= 3

    @patch("builtins.input")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Progress")
    def test_compare_mode_eof_error(
        self, _mock_progress, _mock_console, mock_input
    ):
        """Test compare mode with EOFError."""
        # First input succeeds, then EOFError
        mock_input.side_effect = ["SELECT * FROM test1", "", EOFError(), "", "", ""]

        engine = MagicMock()
        compare_mode(engine)

        # Should not analyze anything due to EOFError
        engine.analyze.assert_not_called()

    @patch("builtins.input")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.Progress")
    def test_compare_mode_second_query_eof_error(
        self, _mock_progress, _mock_console, mock_input
    ):
        """Test compare mode with EOFError on second query."""
        # First query succeeds, second gets EOFError
        mock_input.side_effect = ["SELECT * FROM test1", "", "", EOFError()]

        engine = MagicMock()
        compare_mode(engine)

        # Should not analyze anything due to incomplete second query
        engine.analyze.assert_not_called()


class TestRunAnalysisLoop:
    """Test run_analysis_loop function."""

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    def test_run_analysis_loop_non_interactive(
        self,
        mock_reporter,
        mock_config,
        mock_slowql,
        _mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop in non-interactive mode."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True

        config = MagicMock()
        mock_config.find_and_load.return_value = config
        engine = MagicMock()
        mock_slowql.return_value = engine

        run_analysis_loop(non_interactive=True)

        # Should initialize components
        mock_config.find_and_load.assert_called_once()
        mock_slowql.assert_called_once_with(config=config.with_overrides())
        mock_reporter.assert_called_once()

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    @patch("slowql.cli.app.show_quick_actions_menu")
    @patch("slowql.cli.app.CyberpunkSQLEditor")
    @patch("slowql.cli.app.Confirm")
    @patch("builtins.input")
    def test_run_analysis_loop_with_input(
        self,
        mock_input,
        mock_confirm,
        mock_editor,
        mock_menu,
        _mock_reporter,
        mock_config,
        mock_slowql,
        _mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop with user input."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True
        mock_input.side_effect = ["SELECT * FROM test", "", "quit"]

        # Mock the editor
        mock_editor_instance = MagicMock()
        mock_editor_instance.get_queries.return_value = "SELECT * FROM test"
        mock_editor.return_value = mock_editor_instance

        config = MagicMock()
        mock_config.find_and_load.return_value = config
        engine = MagicMock()
        result = MagicMock()
        engine.analyze.return_value = result
        mock_slowql.return_value = engine

        mock_menu.return_value = False  # Don't continue
        mock_confirm.ask.return_value = False  # No export session

        run_analysis_loop(non_interactive=False)

        # Should analyze the query
        engine.analyze.assert_called_once_with("SELECT * FROM test")

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    @patch("slowql.cli.app.show_quick_actions_menu")
    @patch("slowql.cli.app.Confirm")
    @patch("builtins.input")
    def test_run_analysis_loop_with_file_input(
        self,
        _mock_input,
        mock_confirm,
        mock_menu,
        _mock_reporter,
        mock_config,
        mock_slowql,
        _mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop with file input."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sql", delete=False) as f:
            f.write("SELECT * FROM test_table;")
            temp_file = Path(f.name)

        try:
            config = MagicMock()
            mock_config.find_and_load.return_value = config
            engine = MagicMock()
            result = MagicMock()
            engine.analyze.return_value = result
            mock_slowql.return_value = engine

            mock_menu.return_value = False  # Don't continue
            mock_confirm.ask.return_value = False

            run_analysis_loop(non_interactive=False, initial_input_file=temp_file)

            # Should analyze the file content
            engine.analyze.assert_called_once_with("SELECT * FROM test_table;")
        finally:
            temp_file.unlink()

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    @patch("slowql.cli.app.show_quick_actions_menu")
    @patch("slowql.cli.app.CyberpunkSQLEditor")
    @patch("slowql.cli.app.Confirm")
    @patch("builtins.input")
    def test_run_analysis_loop_with_cache_hit(
        self,
        mock_input,
        mock_confirm,
        mock_editor,
        mock_menu,
        _mock_reporter,
        mock_config,
        mock_slowql,
        _mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop with cache hit."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True
        mock_input.side_effect = ["SELECT * FROM test", "", "quit"]

        # Mock editor
        mock_editor.return_value.get_queries.return_value = "SELECT * FROM test"

        config = MagicMock()
        mock_config.find_and_load.return_value = config
        engine = MagicMock()
        cached_result = MagicMock()
        engine.analyze.return_value = cached_result
        mock_slowql.return_value = engine

        mock_menu.return_value = False  # Don't continue
        mock_confirm.ask.return_value = False

        run_analysis_loop(non_interactive=False, enable_cache=True)

        # Should analyze the query once
        engine.analyze.assert_called_once_with("SELECT * FROM test")

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    @patch("slowql.cli.app.show_quick_actions_menu")
    @patch("slowql.cli.app.compare_mode")
    @patch("slowql.cli.app.Confirm")
    @patch("builtins.input")
    def test_run_analysis_loop_with_comparison_mode(
        self,
        _mock_input,
        _mock_confirm,
        mock_compare,
        _mock_menu,
        _mock_reporter,
        mock_config,
        mock_slowql,
        _mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop with comparison mode enabled."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True

        config = MagicMock()
        mock_config.find_and_load.return_value = config
        engine = MagicMock()
        mock_slowql.return_value = engine

        run_analysis_loop(non_interactive=False, enable_comparison=True)

        # Should call compare_mode
        mock_compare.assert_called_once_with(engine)

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    @patch("slowql.cli.app.show_quick_actions_menu")
    @patch("slowql.cli.app.AnimatedAnalyzer")
    @patch("slowql.cli.app.CyberpunkSQLEditor")
    @patch("slowql.cli.app.Confirm")
    @patch("builtins.input")
    def test_run_analysis_loop_with_animation_exception(
        self,
        mock_input,
        mock_confirm,
        mock_editor,
        mock_animator,
        mock_menu,
        _mock_reporter,
        mock_config,
        mock_slowql,
        _mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop with animation exception."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True
        mock_input.side_effect = ["SELECT * FROM test", "", "quit"]

        # Mock editor
        mock_editor.return_value.get_queries.return_value = "SELECT * FROM test"

        # Mock animation to raise exception
        mock_animator.return_value.particle_loading.side_effect = Exception("Animation failed")

        config = MagicMock()
        mock_config.find_and_load.return_value = config
        engine = MagicMock()
        result = MagicMock()
        engine.analyze.return_value = result
        mock_slowql.return_value = engine

        mock_menu.return_value = False  # Don't continue
        mock_confirm.ask.return_value = False

        # Should not raise exception
        run_analysis_loop(non_interactive=False, fast=False)

        # Should still analyze the query
        engine.analyze.assert_called_once_with("SELECT * FROM test")

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    @patch("slowql.cli.app.show_quick_actions_menu")
    @patch("slowql.cli.app.AnimatedAnalyzer")
    @patch("slowql.cli.app.CyberpunkSQLEditor")
    @patch("slowql.cli.app.Confirm")
    @patch("builtins.input")
    def test_run_analysis_loop_intro_exception(
        self,
        mock_input,
        mock_confirm,
        mock_editor,
        _mock_animator,
        mock_menu,
        _mock_reporter,
        mock_config,
        mock_slowql,
        mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop with intro animation exception."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True
        mock_input.side_effect = ["SELECT * FROM test", "", "quit"]

        # Mock editor
        mock_editor.return_value.get_queries.return_value = "SELECT * FROM test"

        # Mock MatrixRain to raise exception
        mock_matrix.return_value.run.side_effect = Exception("Intro failed")

        config = MagicMock()
        mock_config.find_and_load.return_value = config
        engine = MagicMock()
        result = MagicMock()
        engine.analyze.return_value = result
        mock_slowql.return_value = engine

        mock_menu.return_value = False  # Don't continue
        mock_confirm.ask.return_value = False

        # Should not raise exception
        run_analysis_loop(non_interactive=False, intro_enabled=True, fast=False)

        # Should still analyze the query
        engine.analyze.assert_called_once_with("SELECT * FROM test")

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    @patch("slowql.cli.app.show_quick_actions_menu")
    @patch("slowql.cli.app.Confirm")
    @patch("slowql.cli.app.CyberpunkSQLEditor")
    @patch("builtins.input")
    def test_run_analysis_loop_with_exception_continue(
        self,
        mock_input,
        mock_editor,
        mock_confirm,
        mock_menu,
        _mock_reporter,
        mock_config,
        mock_slowql,
        _mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop with exception and continue."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True
        mock_input.side_effect = ["SELECT * FROM test", "", "SELECT * FROM test2", "", "quit"]

        # Mock editor - return test1 first, then test2
        mock_editor.return_value.get_queries.side_effect = [
            "SELECT * FROM test",
            "SELECT * FROM test2",
        ]

        mock_confirm.ask.return_value = True  # Continue after error

        config = MagicMock()
        mock_config.find_and_load.return_value = config
        engine = MagicMock()
        result = MagicMock()
        engine.analyze.side_effect = [Exception("Analysis failed"), result]
        mock_slowql.return_value = engine

        mock_menu.return_value = False  # Don't continue after successful analysis

        run_analysis_loop(non_interactive=False)

        # Should try to analyze twice, second one succeeds
        assert engine.analyze.call_count == 2

    @patch("slowql.cli.app.sys")
    @patch("slowql.cli.app.console")
    @patch("slowql.cli.app.MatrixRain")
    @patch("slowql.cli.app.SlowQL")
    @patch("slowql.cli.app.Config")
    @patch("slowql.cli.app.ConsoleReporter")
    @patch("slowql.cli.app.show_quick_actions_menu")
    @patch("slowql.cli.app.SessionManager")
    @patch("slowql.cli.app.CyberpunkSQLEditor")
    @patch("slowql.cli.app.Confirm")
    @patch("builtins.input")
    def test_run_analysis_loop_session_summary_export(
        self,
        mock_input,
        mock_confirm,
        mock_editor,
        mock_session_cls,
        mock_menu,
        _mock_reporter,
        mock_config,
        mock_slowql,
        _mock_matrix,
        _mock_console,
        mock_sys,
    ):
        """Test run_analysis_loop with session summary and export."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stdout.isatty.return_value = True
        mock_input.side_effect = ["SELECT * FROM test", "", "quit"]

        # Mock editor
        mock_editor.return_value.get_queries.return_value = "SELECT * FROM test"

        mock_confirm.ask.return_value = True  # Export session

        config = MagicMock()
        mock_config.find_and_load.return_value = config
        engine = MagicMock()
        result = MagicMock()
        engine.analyze.return_value = result
        mock_slowql.return_value = engine

        mock_menu.return_value = False  # Don't continue
        mock_confirm.ask.return_value = True  # Export session

        # Mock session manager and its behavior
        mock_session = MagicMock(spec=SessionManager)
        mock_session_cls.return_value = mock_session
        mock_session.queries_analyzed = 0
        mock_session.total_issues = 0

        def increment_queries_analyzed(_result):
            mock_session.queries_analyzed += 1
            if hasattr(_result, 'issues'):
                mock_session.total_issues += len(_result.issues)

        mock_session.add_analysis.side_effect = increment_queries_analyzed

        run_analysis_loop(non_interactive=False)

        # In non-interactive mode, the session summary should be displayed
        # and the export should be called


class TestArgumentParser:
    """Test argument parser functionality."""

    def test_build_argparser(self):
        """Test argument parser creation."""
        parser = build_argparser()
        assert parser is not None

        # Test parsing basic args
        args = parser.parse_args([])
        assert args.mode == "auto"
        assert args.non_interactive is False

        # Test parsing with file
        args = parser.parse_args(["test.sql"])
        assert args.file == Path("test.sql")

        # Test parsing with options
        args = parser.parse_args(["--mode", "compose", "--fast", "--non-interactive"])
        assert args.mode == "compose"
        assert args.fast is True
        assert args.non_interactive is True


class TestMainFunction:
    """Test main function."""

    @patch("slowql.cli.app.init_cli")
    @patch("slowql.cli.app.build_argparser")
    @patch("slowql.cli.app.run_analysis_loop")
    def test_main(self, mock_run_loop, mock_build_parser, mock_init_cli):
        """Test main function."""
        mock_parser = MagicMock()
        mock_args = MagicMock()
        mock_args.file = None
        mock_args.input_file = None
        mock_args.no_intro = False
        mock_args.duration = 3.0
        mock_args.mode = "auto"
        mock_args.export = None
        mock_args.out = Path("reports")
        mock_args.fast = False
        mock_args.verbose = False
        mock_args.non_interactive = False
        mock_args.no_cache = False
        mock_args.compare = False

        mock_parser.parse_args.return_value = mock_args
        mock_build_parser.return_value = mock_parser

        main()

        mock_init_cli.assert_called_once()
        mock_build_parser.assert_called_once()
        mock_run_loop.assert_called_once_with(
            intro_enabled=True,
            intro_duration=3.0,
            mode="auto",
            initial_input_file=None,
            export_formats=None,
            out_dir=Path("reports"),
            fast=False,
            verbose=False,
            non_interactive=False,
            enable_cache=True,
            enable_comparison=False,
        )
