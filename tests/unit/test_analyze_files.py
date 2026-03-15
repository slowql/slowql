from __future__ import annotations

import tempfile
from pathlib import Path

import slowql
from slowql.core.engine import SlowQL
from slowql.schema.inspector import SchemaInspector


def _tmp(content: str) -> Path:
    with tempfile.NamedTemporaryFile(suffix=".sql", mode="w",
                                     delete=False, encoding="utf-8") as f:
        f.write(content)
        return Path(f.name)


def test_analyze_files_exported():
    assert hasattr(slowql, "analyze_files")


def test_schema_col_fires_across_files():
    ddl = _tmp("CREATE TABLE users (id INT, name VARCHAR(100));")
    qry = _tmp("SELECT id, email FROM users;")
    try:
        result = slowql.analyze_files([ddl, qry])
        rule_ids = [i.rule_id for i in result.issues]
        assert "SCHEMA-COL-001" in rule_ids
    finally:
        ddl.unlink()
        qry.unlink()


def test_schema_tbl_fires_across_files():
    ddl = _tmp("CREATE TABLE users (id INT, name VARCHAR(100));")
    qry = _tmp("SELECT * FROM orders;")
    try:
        result = slowql.analyze_files([ddl, qry])
        rule_ids = [i.rule_id for i in result.issues]
        assert "SCHEMA-TBL-001" in rule_ids
    finally:
        ddl.unlink()
        qry.unlink()


def test_valid_columns_do_not_fire():
    ddl = _tmp("CREATE TABLE users (id INT, name VARCHAR(100));")
    qry = _tmp("SELECT id, name FROM users;")
    try:
        result = slowql.analyze_files([ddl, qry])
        rule_ids = [i.rule_id for i in result.issues]
        assert "SCHEMA-COL-001" not in rule_ids
    finally:
        ddl.unlink()
        qry.unlink()


def test_explicit_schema_not_overwritten():
    schema = SchemaInspector.from_ddl_string(
        "CREATE TABLE users (id INT, email VARCHAR(100));"
    )
    engine = SlowQL()
    engine.schema = schema
    ddl = _tmp("CREATE TABLE users (id INT, name VARCHAR(100));")
    qry = _tmp("SELECT id, email FROM users;")
    try:
        result = engine.analyze_files([ddl, qry])
        rule_ids = [i.rule_id for i in result.issues]
        assert "SCHEMA-COL-001" not in rule_ids
    finally:
        ddl.unlink()
        qry.unlink()


def test_unreadable_file_does_not_crash_schema_detection():
    ddl = _tmp("CREATE TABLE users (id INT, name VARCHAR(100));")
    qry = _tmp("SELECT id, name FROM users;")
    try:
        result = slowql.analyze_files([ddl, "/nonexistent/path.sql", qry])
        assert result is not None
    finally:
        ddl.unlink()
        qry.unlink()


def test_no_ddl_no_schema_rules():
    qry1 = _tmp("SELECT id FROM users;")
    qry2 = _tmp("SELECT name FROM orders;")
    try:
        result = slowql.analyze_files([qry1, qry2])
        rule_ids = [i.rule_id for i in result.issues]
        assert "SCHEMA-COL-001" not in rule_ids
        assert "SCHEMA-TBL-001" not in rule_ids
    finally:
        qry1.unlink()
        qry2.unlink()

