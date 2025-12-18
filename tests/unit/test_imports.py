"""
Test that all modules can be imported and basic instantiation works.
This helps increase coverage by executing import-time code.
"""

from slowql import analyze, analyze_file, core
from slowql.analyzers import base as analyzers_base
from slowql.analyzers import registry as analyzers_registry
from slowql.cli import app as cli_app
from slowql.core.config import Config
from slowql.core.engine import SlowQL
from slowql.core.exceptions import ParseError, SlowQLError
from slowql.core.models import (
    AnalysisResult,
    Dimension,
    Issue,
    Location,
    Query,
    Severity,
)
from slowql.parser import base as parser_base
from slowql.parser import tokenizer, universal
from slowql.rules import base as rules_base
from slowql.rules import catalog


def test_import_core():
    assert core.config
    assert core.engine
    assert core.exceptions
    assert core.models

def test_import_analyzers():
    assert analyzers_base
    assert analyzers_registry

def test_import_parser():
    assert parser_base
    assert tokenizer
    assert universal

def test_import_rules():
    assert rules_base
    assert catalog

def test_import_cli():
    assert cli_app

def test_instantiate_core_classes():
    # Config
    assert Config()

    # Engine
    assert SlowQL(config=Config())

    # Models
    severity = Severity.HIGH
    assert severity

    dimension = Dimension.SECURITY
    assert dimension

    location = Location(line=1, column=1)
    assert location

    issue = Issue(
        rule_id="TEST-001",
        message="Test",
        severity=Severity.MEDIUM,
        dimension=Dimension.QUALITY,
        location=location,
        snippet="code"
    )
    assert issue

    query = Query(
        raw="SELECT * FROM test",
        normalized="SELECT * FROM test",
        dialect="mysql",
        location=location
    )
    assert query

    result = AnalysisResult()
    assert result

    # Exceptions
    error = SlowQLError("test")
    assert error

    parse_error = ParseError("test")
    assert parse_error

def test_instantiate_analyzer_classes():
    # These are abstract, so we can't instantiate directly
    # But we can check they exist
    assert analyzers_base.BaseAnalyzer
    assert analyzers_base.RuleBasedAnalyzer
    assert analyzers_base.PatternAnalyzer
    assert analyzers_registry.AnalyzerRegistry

def test_instantiate_rule_classes():
    # Abstract classes
    assert rules_base.Rule
    assert rules_base.PatternRule
    assert rules_base.ASTRule

def test_instantiate_parser_classes():
    # BaseParser is abstract
    assert parser_base.BaseParser
    assert tokenizer.Tokenizer
    assert universal.UniversalParser

def test_main_functions():
    # These are functions
    assert callable(analyze)
    assert callable(analyze_file)
