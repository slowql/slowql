
from slowql.core.models import AnalysisResult, Location, Query
from slowql.rules.schema.cross_file import CrossFileBreakingChangeRule
from slowql.schema.ddl_parser import DDLParser
from slowql.schema.models import Index, Schema


def test_ddl_parser_extra_coverage() -> None:
    parser = DDLParser()
    schema = Schema()

    # 1. _handle_create_stmt for VIEW
    ddl_view = "CREATE VIEW v1 AS SELECT 1;"
    schema = parser.apply_ddl(ddl_view, schema)
    assert "v1" in schema.views

    # 2. _handle_create_stmt for PROCEDURE
    ddl_proc = "CREATE PROCEDURE p1() AS $$ SELECT 1; $$;"
    schema = parser.apply_ddl(ddl_proc, schema)
    assert "p1" in schema.procedures

    # 3. _handle_create_stmt for Standalone Index
    ddl_table = "CREATE TABLE t1 (id INT);"
    schema = parser.apply_ddl(ddl_table, schema)
    ddl_idxSource = "CREATE INDEX idx1 ON t1 (id);"
    schema = parser.apply_ddl(ddl_idxSource, schema)
    assert len(schema.tables["t1"].indexes) == 1

    # 4. _handle_command_stmt with CREATE
    # Some dialects use Command for certain CREATE statements
    from sqlglot import exp
    cmd = exp.Command(this="CREATE PROCEDURE cmd_proc() AS BEGIN END;")
    schema = parser._handle_command_stmt(cmd, schema)
    assert "cmd_proc" in schema.procedures

    # 5. _handle_drop_stmt for existing table
    schema = parser.apply_ddl("DROP TABLE t1;", schema)
    assert "t1" not in schema.tables

    # 6. _finalize_indexes for non-existent table (coverage)
    schema = parser._finalize_indexes(schema, [("non_existent", Index(name="idx", columns=("id",)))])
    assert "non_existent" not in schema.tables

def test_cross_file_rule_edge_cases() -> None:
    rule = CrossFileBreakingChangeRule()

    # 1. No DDL queries (coverage for empty breaking_queries)
    res = AnalysisResult(dialect="universal", queries=[
        Query(raw="SELECT 1;", normalized="SELECT 1;", dialect="universal", location=Location(1, 1))
    ])
    assert rule.check_project(res) == []

    # 2. DDL query with no AST (coverage for if not ddl_query.ast)
    res = AnalysisResult(dialect="universal", queries=[
        Query(raw="INVALID SQL;", normalized="INVALID SQL;", dialect="universal", location=Location(1, 1), is_ddl=True)
    ])
    assert rule.check_project(res) == []

def test_cross_file_rule_extra_coverage() -> None:
    rule = CrossFileBreakingChangeRule()

    # 1. _extract_dropped_objects with complex ALTER (already covered but good to be explicit)
    from sqlglot import parse_one
    ast = parse_one("ALTER TABLE t1 DROP COLUMN c1, DROP COLUMN c2;", read="postgres")
    tables, columns = rule._extract_dropped_objects(ast)
    assert "t1" in columns
    assert "c1" in columns["t1"]
    assert "c2" in columns["t1"]

    # 2. _extract_dropped_objects with DROP TABLE
    ast_drop = parse_one("DROP TABLE t2;", read="postgres")
    tables, columns = rule._extract_dropped_objects(ast_drop)
    assert "t2" in tables

    # 3. Test breaking column in DIFFERENT file
    res = AnalysisResult(dialect="universal", queries=[
        Query(
            raw="ALTER TABLE users DROP COLUMN email;",
            normalized="ALTER TABLE users DROP COLUMN email;",
            dialect="universal",
            location=Location(1, 1, file="breaking.sql"),
            is_ddl=True,
            ast=parse_one("ALTER TABLE users DROP COLUMN email;")
        ),
        Query(
            raw="SELECT email FROM users;",
            normalized="SELECT email FROM users;",
            dialect="universal",
            location=Location(2, 1, file="query.sql"),
            tables=("users",),
            columns=("email",)
        )
    ])
    issues = rule.check_project(res)
    assert len(issues) == 1
    assert "query.sql" in issues[0].message
