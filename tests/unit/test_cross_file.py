from pathlib import Path

from slowql.core.engine import SlowQL
from slowql.schema.ddl_parser import DDLParser


def test_ddl_parser_views() -> None:
    parser = DDLParser()
    ddl = """
    CREATE TABLE users (id INT PRIMARY KEY, name TEXT);
    CREATE VIEW active_users AS SELECT * FROM users WHERE active = true;
    """
    schema = parser.parse_ddl(ddl)

    assert "active_users" in schema.views
    view = schema.views["active_users"]
    assert view.name == "active_users"
    assert "users" in view.dependencies

def test_ddl_parser_procedures() -> None:
    parser = DDLParser()
    ddl = """
    CREATE PROCEDURE update_status(user_id INT)
    LANGUAGE SQL
    AS $$
    UPDATE users SET status = 'updated' WHERE id = user_id;
    CALL log_change(user_id, 'status_updated');
    $$;
    """
    schema = parser.parse_ddl(ddl)

    assert "update_status" in schema.procedures
    proc = schema.procedures["update_status"]
    assert proc.name == "update_status"
    assert "log_change" in proc.calls

def test_cross_file_breaking_change(tmp_path: Path) -> None:
    # Setup files
    schema_file = tmp_path / "schema.sql"
    schema_file.write_text("CREATE TABLE users (id INT PRIMARY KEY, email TEXT);")

    query_file = tmp_path / "query.sql"
    query_file.write_text("SELECT email FROM users;")

    breaking_file = tmp_path / "breaking.sql"
    breaking_file.write_text("ALTER TABLE users DROP COLUMN email;")

    engine = SlowQL()
    result = engine.analyze_files([schema_file, query_file, breaking_file])

    # We expect an issue in breaking.sql because it breaks query.sql
    breaking_issues = [i for i in result.issues if "breaking.sql" in (i.location.file or "")]
    assert any("Breaking Change" in i.message for i in breaking_issues)
    assert any("email" in i.message for i in breaking_issues)

def test_view_dependency_tracking(tmp_path: Path) -> None:
    # Setup files
    base_file = tmp_path / "base.sql"
    base_file.write_text("CREATE TABLE base_table (id INT);")

    view1_file = tmp_path / "view1.sql"
    view1_file.write_text("CREATE VIEW v1 AS SELECT * FROM base_table;")

    view2_file = tmp_path / "view2.sql"
    view2_file.write_text("CREATE VIEW v2 AS SELECT * FROM v1;")

    engine = SlowQL()
    engine.analyze_files([base_file, view1_file, view2_file])

    # Verify that the schema built contains all views and their dependencies
    schema = engine.schema
    assert schema is not None
    assert "v1" in schema.views
    assert "v2" in schema.views
    assert "base_table" in schema.views["v1"].dependencies
    assert "v1" in schema.views["v2"].dependencies

def test_procedure_call_graph(tmp_path: Path) -> None:
    # Setup files
    p1_file = tmp_path / "proc1.sql"
    p1_file.write_text("CREATE PROCEDURE p1() AS $$ CALL p2(); $$;")

    p2_file = tmp_path / "proc2.sql"
    p2_file.write_text("CREATE PROCEDURE p2() AS $$ SELECT 1; $$;")

    engine = SlowQL()
    engine.analyze_files([p1_file, p2_file])

    schema = engine.schema
    assert schema is not None
    assert "p1" in schema.procedures
    assert "p2" in schema.procedures
    assert "p2" in schema.procedures["p1"].calls
