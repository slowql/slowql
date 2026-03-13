"""Tests for schema-aware CLI functionality."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from slowql.cli.app import main, run_analysis_loop


def test_run_analysis_loop_with_schema(tmp_path):
    """Test that run_analysis_loop correctly loads a schema and passes it to SlowQL."""
    schema_file = tmp_path / "schema.sql"
    schema_file.write_text("CREATE TABLE users (id INT);")

    sql_file = tmp_path / "query.sql"
    sql_file.write_text("SELECT * FROM users;")

    with patch("slowql.cli.app.SlowQL") as mock_slowql, \
         patch("slowql.cli.app.Config.find_and_load") as mock_config, \
         patch("slowql.schema.inspector.SchemaInspector.from_ddl_file") as mock_inspector:

        mock_config.return_value.analysis.dialect = "postgresql"
        mock_schema = MagicMock()
        mock_inspector.return_value = mock_schema

        # Run the loop in non-interactive mode
        run_analysis_loop(
            non_interactive=True,
            initial_input_file=sql_file,
            schema_file=schema_file,
            intro_enabled=False
        )

        # Verify schema loading
        mock_inspector.assert_called_once_with(schema_file, dialect="postgresql")

        # Verify SlowQL initialization with schema
        mock_slowql.assert_called_once()
        kwargs = mock_slowql.call_args.kwargs
        assert kwargs["schema"] == mock_schema

def test_main_passes_schema_to_loop():
    """Test that main() correctly extracts the --schema argument and passes it to run_analysis_loop."""
    with patch("slowql.cli.app.run_analysis_loop") as mock_run_loop, \
         patch("slowql.cli.app.init_cli"):

        main(["query.sql", "--schema", "schema.sql"])

        # Verify that schema_file was passed in loop_kwargs
        mock_run_loop.assert_called_once()
        kwargs = mock_run_loop.call_args.kwargs
        assert kwargs["schema_file"] == Path("schema.sql")


def test_run_analysis_loop_config_schema_fallback(tmp_path):
    """Test that run_analysis_loop falls back to config.schema.path."""
    sql_file = tmp_path / "query.sql"
    sql_file.write_text("SELECT * FROM users;")

    with patch("slowql.cli.app.SlowQL") as mock_slowql, \
         patch("slowql.cli.app.Config.find_and_load") as mock_config, \
         patch("slowql.schema.inspector.SchemaInspector.from_ddl_file") as mock_inspector:

        # Mock config with schema.path
        mock_config.return_value.schema_config.path = "config/schema.sql"
        mock_config.return_value.analysis.dialect = "postgresql"

        mock_schema = MagicMock()
        mock_inspector.return_value = mock_schema

        # Run without explicit schema_file
        run_analysis_loop(
            non_interactive=True,
            initial_input_file=sql_file,
            schema_file=None,
            intro_enabled=False
        )

        # Verify it loaded from config path
        mock_inspector.assert_called_once_with(Path("config/schema.sql"), dialect="postgresql")
        assert mock_slowql.call_args.kwargs["schema"] == mock_schema


def test_run_analysis_loop_cli_overrides_config(tmp_path):
    """Test that CLI --schema overrides config.schema.path."""
    sql_file = tmp_path / "query.sql"
    sql_file.write_text("SELECT * FROM users;")
    cli_schema = tmp_path / "cli.sql"

    with patch("slowql.cli.app.SlowQL"), \
         patch("slowql.cli.app.Config.find_and_load") as mock_config, \
         patch("slowql.schema.inspector.SchemaInspector.from_ddl_file") as mock_inspector:

        # Mock config with schema.path
        mock_config.return_value.schema_config.path = "config/schema.sql"
        mock_config.return_value.analysis.dialect = "postgresql"

        # Explicit CLI schema
        run_analysis_loop(
            non_interactive=True,
            initial_input_file=sql_file,
            schema_file=cli_schema,
            intro_enabled=False
        )

        # Verify it loaded FROM CLI path, NOT config path
        mock_inspector.assert_called_once_with(cli_schema, dialect="postgresql")
