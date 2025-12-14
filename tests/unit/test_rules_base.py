
import re
from unittest.mock import MagicMock
from slowql.rules.base import (
    Rule,
    RuleMetadata,
    PatternRule,
    ASTRule,
    create_rule
)
from slowql.core.models import (
    Category,
    Dimension,
    Severity,
    Issue,
    Location,
    Query
)

QUERY_RAW = "SELECT * FROM users"
QUERY_NORMALIZED = "SELECT * FROM users"

class TestRuleMetadata:
    def test_metadata_to_dict(self):
        meta = RuleMetadata(
            id="TEST-001",
            name="Test Rule",
            description="Test Description",
            severity=Severity.HIGH,
            dimension=Dimension.SECURITY,
            category=Category.SEC_INJECTION,
            impact="High impact",
            rationale="Because",
            examples=("ex1", "ex2"),
            references=("ref1",),
            tags=("tag1",),
            fix_guidance="Do this",
        )
        data = meta.to_dict()
        assert data["id"] == "TEST-001"
        assert data["name"] == "Test Rule"
        assert data["severity"] == Severity.HIGH.value
        assert data["dimension"] == Dimension.SECURITY.value
        assert data["category"] == Category.SEC_INJECTION.value
        assert data["examples"] == ["ex1", "ex2"]
        assert data["references"] == ["ref1"]
        assert data["tags"] == ["tag1"]
        assert data["documentation_url"] == "https://slowql.dev/rules/test-001"


class ConcreteRule(Rule):
    id = "CONCRETE-001"
    name = "Concrete Rule"
    description = "Concrete Description"
    severity = Severity.MEDIUM
    dimension = Dimension.PERFORMANCE
    
    def check(self, query):
        return []

class TestRuleBase:
    def test_rule_repr_str(self):
        rule = ConcreteRule()
        assert repr(rule) == "ConcreteRule(id='CONCRETE-001')"
        assert str(rule) == "[CONCRETE-001] Concrete Rule"

    def test_rule_metadata_property(self):
        rule = ConcreteRule()
        meta = rule.metadata
        assert isinstance(meta, RuleMetadata)
        assert meta.id == "CONCRETE-001"
        assert meta.severity == Severity.MEDIUM

    def test_create_issue(self):
        rule = ConcreteRule()
        query = Query(
            raw=QUERY_RAW,
            normalized=QUERY_NORMALIZED,
            dialect="postgres",
            location=Location(line=1, column=1)
        )
        issue = rule.create_issue(
            query=query,
            message="Found issue",
            snippet="SELECT *"
        )
        assert isinstance(issue, Issue)
        assert issue.rule_id == "CONCRETE-001"
        assert issue.message == "Found issue"
        assert issue.snippet == "SELECT *"
        assert issue.severity == Severity.MEDIUM
        assert issue.location == query.location

    def test_regex_helpers(self):
        rule = ConcreteRule()
        pat = r"select"
        
        # Test _compile_pattern caching
        p1 = rule._compile_pattern(pat)
        p2 = rule._compile_pattern(pat)
        assert p1 is p2
        
        # Test _has_pattern
        assert rule._has_pattern("select *", pat)
        assert not rule._has_pattern("delete *", pat)
        
        # Test _find_pattern
        matches = rule._find_pattern("select select", pat)
        assert len(matches) == 2


class TestASTRuleBase:
    def test_check_ast_wrapper(self):
        # Test that check() calls check_ast() if ast is present
        class MyASTRule(ASTRule):
            id = "AST-001"
            name = "AST Rule"
            check_ast = MagicMock(return_value=[])
            
        rule = MyASTRule()
        query = Query(
            raw=QUERY_RAW,
            normalized=QUERY_NORMALIZED,
            dialect="postgres",
            location=Location(line=1, column=1),
            ast=MagicMock() # Mock AST
        )
        rule.check(query)
        rule.check_ast.assert_called_once_with(query, query.ast)
        
        # Test with no AST
        query_no_ast = Query(
            raw=QUERY_RAW,
            normalized=QUERY_NORMALIZED,
            dialect="postgres",
            location=Location(line=1, column=1),
            ast=None
        )
        rule.check_ast.reset_mock()
        assert rule.check(query_no_ast) == []
        rule.check_ast.assert_not_called()

    def test_ast_helpers(self):
        # We need to mock sqlglot components since we don't want to rely on real parsing here if possible,
        # or we use real parsing if sqlglot is available.
        # Given the previous existing tests use real queries, let's try to mock the AST structure 
        # that the helpers expect: find, find_all.
        
        class HelperRule(ASTRule):
            id = "HELPER-001"
            name = "Helper"
            def check_ast(self, q, a): return []

        rule = HelperRule()
        
        # Mock AST for _has_where_clause
        from sqlglot import exp
        mock_ast = MagicMock()
        mock_ast.find.return_value = "WhereNode"
        assert rule._has_where_clause(mock_ast) is True
        mock_ast.find.assert_called_with(exp.Where)
        
        mock_ast.find.return_value = None
        assert rule._has_where_clause(mock_ast) is False

        # Mock AST for _get_tables
        mock_table = MagicMock()
        mock_table.name = "users"
        mock_ast.find_all.return_value = [mock_table]
        assert rule._get_tables(mock_ast) == ["users"]
        mock_ast.find_all.assert_called_with(exp.Table)

        # Mock AST for _get_columns
        mock_col = MagicMock()
        mock_col.name = "id"
        mock_ast.find_all.return_value = [mock_col]
        assert rule._get_columns(mock_ast) == ["id"]
        mock_ast.find_all.assert_called_with(exp.Column)
        
        # Mock AST for _get_functions
        mock_func = MagicMock()
        mock_func.name = "count"
        mock_ast.find_all.return_value = [mock_func]
        assert rule._get_functions(mock_ast) == ["count"]


class TestCreateRuleFactory:
    def test_create_rule(self):
        def my_check(query):
            return [Issue(rule_id="test", message="msg", severity=Severity.LOW, dimension=Dimension.QUALITY, location=query.location, snippet="")]
        
        rule = create_rule(
            id="DYN-001",
            name="Dynamic Rule",
            description="Dynamic Desc",
            severity=Severity.LOW,
            dimension=Dimension.QUALITY,
            check_fn=my_check,
            category=Category.QUAL_READABILITY,
            tags=("dynamic",),
            impact="None",
            fix_guidance="Fix it"
        )
        
        assert isinstance(rule, Rule)
        assert rule.id == "DYN-001"
        assert rule.name == "Dynamic Rule"
        assert rule.category == Category.QUAL_READABILITY
        assert rule.tags == ("dynamic",)
        
        query = Query(raw="", normalized="", dialect="", location=Location(line=1, column=1))
        issues = rule.check(query)
        assert len(issues) == 1
        assert issues[0].message == "msg"
