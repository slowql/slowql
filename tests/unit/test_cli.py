# tests/unit/test_cli.py
"""
Test CLI functionality.
"""

from slowql.cli import app


def test_cli_app_import():
    """Test that CLI app can be imported."""
    assert app is not None


def test_cli_main_function():
    """Test that main function exists."""
    assert hasattr(app, 'main')
    assert callable(app.main)