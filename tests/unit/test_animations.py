"""Tests for CLI UI animations."""

import time
from unittest.mock import patch, MagicMock

import pytest

from slowql.cli.ui.animations import MatrixRain, CyberpunkSQLEditor, AnimatedAnalyzer


class TestMatrixRain:
    """Test MatrixRain class."""

    @patch("slowql.cli.ui.animations.shutil.get_terminal_size")
    @patch("slowql.cli.ui.animations.Console")
    def test_init(self, mock_console, mock_get_terminal_size):
        """Test MatrixRain initialization."""
        mock_get_terminal_size.return_value = MagicMock(columns=80, lines=24)

        rain = MatrixRain()

        assert rain.width == 80
        assert rain.height == 24
        assert len(rain.columns) == 80
        assert isinstance(rain.logo_ascii, list)
        assert len(rain.logo_ascii) == 6

    @patch("slowql.cli.ui.animations.shutil.get_terminal_size")
    @patch("slowql.cli.ui.animations.Console")
    def test_get_logo_color(self, mock_console, mock_get_terminal_size):
        """Test logo color generation."""
        mock_get_terminal_size.return_value = MagicMock(columns=80, lines=24)

        rain = MatrixRain()

        # Test different positions
        assert "cyan" in rain._get_logo_color(0, 50)  # Arrow area
        assert "deep_sky_blue1" in rain._get_logo_color(10, 50)  # S-L area
        assert "medium_purple1" in rain._get_logo_color(20, 50)  # O-W area
        assert "magenta" in rain._get_logo_color(30, 50)  # Q area
        assert "hot_pink" in rain._get_logo_color(40, 50)  # L area

    @patch("slowql.cli.ui.animations.shutil.get_terminal_size")
    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Live")
    @patch("slowql.cli.ui.animations.time.sleep")
    @patch("builtins.input")
    def test_run_short_duration(self, mock_input, mock_sleep, mock_live, mock_console, mock_get_terminal_size):
        """Test MatrixRain run with short duration."""
        mock_get_terminal_size.return_value = MagicMock(columns=80, lines=24)
        mock_input.return_value = ""  # Simulate enter press

        rain = MatrixRain()
        rain.run(duration=0.1)  # Very short duration

        # Should have called Live and sleep
        mock_live.assert_called_once()
        mock_sleep.assert_called()

    @patch("slowql.cli.ui.animations.shutil.get_terminal_size")
    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Align")
    @patch("slowql.cli.ui.animations.Text")
    @patch("slowql.cli.ui.animations.time.sleep")
    @patch("builtins.input")
    def test_slow_scroll_reveal(self, mock_input, mock_sleep, mock_text, mock_align, mock_console, mock_get_terminal_size):
        """Test slow scroll reveal functionality."""
        mock_get_terminal_size.return_value = MagicMock(columns=80, lines=24)
        mock_input.return_value = ""  # Simulate enter press

        rain = MatrixRain()
        rain._slow_scroll_reveal()

        # Should have called console methods
        mock_console.return_value.clear.assert_called_once()
        mock_console.return_value.print.assert_called()


class TestCyberpunkSQLEditor:
    """Test CyberpunkSQLEditor class."""

    @patch("slowql.cli.ui.animations.Console")
    def test_init(self, mock_console):
        """Test CyberpunkSQLEditor initialization."""
        editor = CyberpunkSQLEditor()
        assert editor.console is not None

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Prompt")
    @patch("slowql.cli.ui.animations.Align")
    @patch("slowql.cli.ui.animations.Panel")
    def test_get_queries_empty(self, mock_panel, mock_align, mock_prompt, mock_console):
        """Test get_queries with empty input."""
        mock_prompt.ask.side_effect = ["", ""]  # Two empty lines to finish

        editor = CyberpunkSQLEditor()
        result = editor.get_queries()

        assert result == ""

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Prompt")
    @patch("slowql.cli.ui.animations.Align")
    @patch("slowql.cli.ui.animations.Panel")
    @patch("slowql.cli.ui.animations.Syntax")
    def test_get_queries_with_content(self, mock_syntax, mock_panel, mock_align, mock_prompt, mock_console):
        """Test get_queries with actual SQL content."""
        mock_prompt.ask.side_effect = ["SELECT * FROM test", "", ""]  # Query then two empties

        editor = CyberpunkSQLEditor()
        result = editor.get_queries()

        assert result == "SELECT * FROM test"

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Prompt")
    def test_get_queries_keyboard_interrupt(self, mock_prompt, mock_console):
        """Test get_queries with keyboard interrupt."""
        mock_prompt.ask.side_effect = KeyboardInterrupt()

        editor = CyberpunkSQLEditor()
        result = editor.get_queries()

        assert result is None

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Align")
    @patch("slowql.cli.ui.animations.Panel")
    def test_show_header(self, mock_panel, mock_align, mock_console):
        """Test header display."""
        editor = CyberpunkSQLEditor()
        editor._show_header()

        mock_console.return_value.print.assert_called_once()

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Panel")
    @patch("slowql.cli.ui.animations.Syntax")
    def test_show_query_preview(self, mock_syntax, mock_panel, mock_console):
        """Test query preview display."""
        editor = CyberpunkSQLEditor()
        editor._show_query_preview("SELECT * FROM test")

        mock_console.return_value.print.assert_called_once()

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Align")
    @patch("slowql.cli.ui.animations.Panel")
    @patch("rich.rule.Rule")
    @patch("slowql.cli.ui.animations.time.sleep")
    def test_show_query_summary(self, mock_sleep, mock_rule, mock_panel, mock_align, mock_console):
        """Test query summary display."""
        editor = CyberpunkSQLEditor()
        editor._show_query_summary(["SELECT * FROM test", ""])

        # Should print multiple times for summary
        assert mock_console.return_value.print.call_count >= 2


class TestAnimatedAnalyzer:
    """Test AnimatedAnalyzer class."""

    @patch("slowql.cli.ui.animations.Console")
    def test_init(self, mock_console):
        """Test AnimatedAnalyzer initialization."""
        analyzer = AnimatedAnalyzer()
        assert analyzer.console is not None
        assert len(analyzer.gradient_colors) == 5

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.time.sleep")
    def test_glitch_transition(self, mock_sleep, mock_console):
        """Test glitch transition effect."""
        analyzer = AnimatedAnalyzer()
        analyzer.glitch_transition(duration=0.1)

        # Should have printed multiple glitch lines
        assert mock_console.return_value.print.call_count > 0

    @patch("slowql.cli.ui.animations.shutil.get_terminal_size")
    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Live")
    @patch("slowql.cli.ui.animations.Panel")
    @patch("slowql.cli.ui.animations.time.sleep")
    def test_particle_loading(self, mock_sleep, mock_panel, mock_live, mock_console, mock_get_terminal_size):
        """Test particle loading animation."""
        mock_get_terminal_size.return_value = MagicMock(columns=80, lines=24)

        analyzer = AnimatedAnalyzer()
        analyzer.particle_loading("TESTING")

        mock_live.assert_called_once()

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Panel")
    @patch("slowql.cli.ui.animations.time.sleep")
    def test_reveal_section(self, mock_sleep, mock_panel, mock_console):
        """Test section reveal animation."""
        analyzer = AnimatedAnalyzer()
        analyzer.reveal_section("test content", "Test Title", "cyan")

        # Should print 3 times (dim, normal, bold)
        assert mock_console.return_value.print.call_count == 3

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Panel")
    @patch("builtins.input")
    @patch("slowql.cli.ui.animations.contextlib.suppress")
    def test_show_expandable_details_not_expanded(self, mock_suppress, mock_input, mock_panel, mock_console):
        """Test expandable details when not expanded."""
        analyzer = AnimatedAnalyzer()
        analyzer.show_expandable_details("summary", "details", expanded=False)

        # Should print summary panel first
        assert mock_console.return_value.print.call_count >= 1

    @patch("slowql.cli.ui.animations.Console")
    @patch("slowql.cli.ui.animations.Panel")
    def test_show_expandable_details_expanded(self, mock_panel, mock_console):
        """Test expandable details when already expanded."""
        analyzer = AnimatedAnalyzer()
        analyzer.show_expandable_details("summary", "details", expanded=True)

        # Should go directly to reveal_section
        assert mock_console.return_value.print.call_count >= 1