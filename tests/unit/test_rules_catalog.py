from unittest.mock import MagicMock

from sqlglot import exp

from slowql.core.models import Location, Query
from slowql.rules.catalog import (
    DistinctOnLargeSetRule,
    DropTableRule,
    GrantAllRule,
    ImplicitJoinRule,
    MissingWhereRule,
)

QUERY_LOC = Location(line=1, column=1)


def create_query(raw, query_type="SELECT"):
    return Query(
        raw=raw,
        normalized=raw,
        dialect="postgres",
        location=QUERY_LOC,
        query_type=query_type,
        ast=None,
    )


class TestCatalogRules:
    def test_grant_all_rule(self):
        rule = GrantAllRule()

        # Test GRANT ALL
        # Manually construct AST to ensure it matches what Rule expects
        ast = exp.Grant(actions=[exp.Literal.string("ALL")])
        query = create_query("GRANT ALL ...", "GRANT")

        # Helper to inject 'actions' attribute, which may not be exposed via __init__.
        # Actually exp.Grant has 'actions' arg usually.
        # But let's check what the rule accesses: ast.actions

        issues = rule.check_ast(query, ast)
        # Note: The rule checks 'actions' attribute. sqlglot puts actions in 'actions' arg.
        # However, sqlglot nodes usually store args in .args dictionary.
        # The rule does `raw_actions = getattr(ast, "actions", None) or []`.
        # sqlglot expression properties are usually dynamic.
        # Let's enforce it for the test.
        if not hasattr(ast, "actions"):
            # Mock it if sqlglot version is diff
            ast.actions = [exp.Literal.string("ALL")]

        # Wait, the rule does `getattr(ast, "actions")`.
        # If I construct via exp.Grant(actions=[...]), it should be in .args['actions'].
        # Does .actions property exist?
        # Let's assume the rule was written knowing sqlglot API.

        # If the original rule uses `getattr(ast, "actions", None)`, implies it expects a property.
        # Let's just mock the AST object completely to be safe and purely test logic.

        mock_ast = MagicMock(spec=exp.Grant)
        mock_ast.actions = [MagicMock(name="ALL")]
        # The rule checks for .name or str(action)
        mock_ast.actions[0].name = "ALL"

        issues = rule.check_ast(query, mock_ast)
        assert len(issues) == 1
        assert "GRANT ALL" in issues[0].message

        # Test GRANT SELECT
        mock_ast.actions = [MagicMock(name="SELECT")]
        issues = rule.check_ast(query, mock_ast)
        assert len(issues) == 0

    def test_drop_table_rule(self):
        rule = DropTableRule()

        # Test DROP TABLE
        ast = exp.Drop()
        query = create_query("DROP TABLE ...", "DROP")

        issues = rule.check_ast(query, ast)
        assert len(issues) == 1
        assert "DROP statement detected" in issues[0].message

        # Test other statement
        ast = exp.Select()
        query = create_query("SELECT ...", "SELECT")
        issues = rule.check_ast(query, ast)
        assert len(issues) == 0

    def test_implicit_join_rule(self):
        rule = ImplicitJoinRule()

        # Test implicit join
        # Construct AST: SELECT * FROM t1, t2
        ast = exp.Select()
        from_clause = exp.From()
        # Ensure has multiple expressions
        t1 = exp.Table(this=exp.Identifier(this="t1", quoted=False))
        t2 = exp.Table(this=exp.Identifier(this="t2", quoted=False))
        from_clause.set("expressions", [t1, t2])
        ast.set("from", from_clause)

        query = create_query("SELECT * FROM t1, t2", "SELECT")

        issues = rule.check_ast(query, ast)
        assert len(issues) == 1
        assert "Implicit join syntax" in issues[0].message

        # Test explicit join (FROM has 1 table usually, JOINs are separate)
        ast = exp.Select()
        from_clause = exp.From()
        from_clause.set("expressions", [t1])
        ast.set("from", from_clause)

        query = create_query("SELECT * FROM t1 JOIN t2 ...", "SELECT")
        issues = rule.check_ast(query, ast)
        assert len(issues) == 0

    def test_missing_where_rule(self):
        rule = MissingWhereRule()

        # Test UPDATE without WHERE
        ast = exp.Update()
        # ast.find(exp.Where) -> None
        query = create_query("UPDATE ...", "UPDATE")

        issues = rule.check_ast(query, ast)
        assert len(issues) == 1
        assert "missing WHERE" in issues[0].message

        # Test UPDATE with WHERE
        ast = exp.Update()
        ast.set("where", exp.Where())
        # sqlglot convention: .set("where", ...) might not automatically make .find(exp.Where) work
        # if the structure isn't perfect, but usually find traverses args.

        # Manually ensure find returns something
        # Better: mock the AST
        mock_ast = MagicMock()
        mock_ast.find.return_value = MagicMock()  # Found WHERE

        issues = rule.check_ast(query, mock_ast)
        assert len(issues) == 0

        # Test DELETE without WHERE
        mock_ast.find.return_value = None
        query = create_query("DELETE ...", "DELETE")
        issues = rule.check_ast(query, mock_ast)
        assert len(issues) == 1

    def test_distinct_on_large_set_rule(self):
        rule = DistinctOnLargeSetRule()

        # Test DISTINCT
        # ast.args.get("distinct") must be truthy
        mock_ast = MagicMock(spec=exp.Select)
        mock_ast.args = {"distinct": True}

        query = create_query("SELECT DISTINCT ...", "SELECT")

        issues = rule.check_ast(query, mock_ast)
        assert len(issues) == 1
        assert "DISTINCT usage detected" in issues[0].message

        # Test normal SELECT
        mock_ast.args = {"distinct": False}
        query = create_query("SELECT ...", "SELECT")

        issues = rule.check_ast(query, mock_ast)
        assert len(issues) == 0
