from sqlglot import parse_one

from slowql.core.models import Location, Query
from slowql.rules.migration.breaking_change import BreakingChangeRule
from slowql.schema.models import Column, ColumnType, Schema, Table


def test_breaking_change_drop_table():
    schema = Schema(tables={
        "users": Table(name="users", columns=(
            Column(name="id", type=ColumnType.INTEGER),
        ))
    })
    rule = BreakingChangeRule(schema)

    query = Query(
        raw="DROP TABLE users",
        normalized="DROP TABLE users",
        dialect="postgresql",
        ast=parse_one("DROP TABLE users"),
        location=Location(line=1, column=1, file="migration.sql")
    )

    issues = rule.check(query)
    assert len(issues) == 1
    assert "Dropping table 'users'" in issues[0].message

def test_breaking_change_drop_column():
    schema = Schema(tables={
        "users": Table(name="users", columns=(
            Column(name="id", type=ColumnType.INTEGER),
            Column(name="email", type=ColumnType.TEXT),
        ))
    })
    rule = BreakingChangeRule(schema)

    query = Query(
        raw="ALTER TABLE users DROP COLUMN email",
        normalized="ALTER TABLE users DROP COLUMN email",
        dialect="postgresql",
        ast=parse_one("ALTER TABLE users DROP COLUMN email"),
        location=Location(line=1, column=1, file="migration.sql")
    )

    issues = rule.check(query)
    assert len(issues) == 1
    assert "Dropping column 'email'" in issues[0].message

def test_no_issue_if_table_missing_in_before_schema():
    # If table doesn't exist in previous schema, dropping it isn't a "breaking change"
    # (maybe it was created in the same migration transaction or something,
    # but the rule specifically checks against schema_before)
    schema = Schema(tables={})
    rule = BreakingChangeRule(schema)

    query = Query(
        raw="DROP TABLE users",
        normalized="DROP TABLE users",
        dialect="postgresql",
        ast=parse_one("DROP TABLE users"),
        location=Location(line=1, column=1, file="migration.sql")
    )

    issues = rule.check(query)
    assert len(issues) == 0

def test_breaking_change_none_schema():
    rule = BreakingChangeRule(None)
    query = Query(
        raw="DROP TABLE users",
        normalized="DROP TABLE users",
        dialect="postgresql",
        ast=parse_one("DROP TABLE users"),
        location=Location(line=1, column=1, file="migration.sql")
    )
    assert len(rule.check(query)) == 0
