import slowql
from slowql.core.engine import SlowQL
from slowql.schema.inspector import SchemaInspector

DDL = "CREATE TABLE users (id INT, name VARCHAR(100));"

def test_schema_col_fires_on_nonexistent_column():
    result = slowql.analyze(f"{DDL}\nSELECT id, email FROM users")
    rule_ids = [i.rule_id for i in result.issues]
    assert "SCHEMA-COL-001" in rule_ids

def test_schema_col_does_not_fire_on_valid_column():
    result = slowql.analyze(f"{DDL}\nSELECT id, name FROM users")
    rule_ids = [i.rule_id for i in result.issues]
    assert "SCHEMA-COL-001" not in rule_ids

def test_schema_tbl_fires_on_nonexistent_table():
    result = slowql.analyze(f"{DDL}\nSELECT * FROM orders")
    rule_ids = [i.rule_id for i in result.issues]
    assert "SCHEMA-TBL-001" in rule_ids

def test_explicit_schema_not_overwritten():
    # Explicit schema takes priority over DDL auto-detection
    schema = SchemaInspector.from_ddl_string(
        "CREATE TABLE users (id INT, email VARCHAR(100));"
    )
    engine = SlowQL()
    engine.schema = schema
    # email exists in explicit schema but DDL says name — explicit wins
    result = engine.analyze(f"{DDL}\nSELECT id, email FROM users")
    rule_ids = [i.rule_id for i in result.issues]
    assert "SCHEMA-COL-001" not in rule_ids

def test_no_ddl_no_schema_rules():
    result = slowql.analyze("SELECT id, email FROM users")
    rule_ids = [i.rule_id for i in result.issues]
    assert "SCHEMA-COL-001" not in rule_ids
    assert "SCHEMA-TBL-001" not in rule_ids

def test_ddl_parse_failure_does_not_crash():
    # Malformed DDL should not crash analysis
    result = slowql.analyze("CREATE TABLE (broken; SELECT 1")
    assert result is not None

def test_multiple_tables_detected():
    ddl = """
    CREATE TABLE users (id INT, name VARCHAR(100));
    CREATE TABLE orders (id INT, user_id INT, amount DECIMAL);
    """
    result = slowql.analyze(f"{ddl}\nSELECT id, email FROM users")
    rule_ids = [i.rule_id for i in result.issues]
    assert "SCHEMA-COL-001" in rule_ids
