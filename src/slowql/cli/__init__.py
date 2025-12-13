# slowql/src/slowql/cli/__init__.py
"""
CLI module for SlowQL.

This module provides the command-line interface logic,
using Typer for argument parsing and command dispatch.
"""

from slowql.cli.app import main

__all__ = ["main"]