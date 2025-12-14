# tests/unit/test_imports.py
"""
Test that all modules can be imported and basic instantiation works.
This helps increase coverage by executing import-time code.
"""

def test_import_core():
    from slowql.core import config, engine, exceptions, models
    assert config
    assert engine
    assert exceptions
    assert models

def test_import_analyzers():
    from slowql.analyzers import base, registry
    assert base
    assert registry

def test_import_parser():
    from slowql.parser import base, tokenizer, universal
    assert base
    assert tokenizer
    assert universal

def test_import_rules():
    from slowql.rules import base, catalog
    assert base
    assert catalog

def test_import_cli():
    from slowql.cli import app
    assert app

def test_instantiate_core_classes():
    from slowql.core.config import Config
    from slowql.core.engine import SlowQL
    from slowql.core.models import Severity, Dimension, Location, Issue, Query, AnalysisResult
    from slowql.core.exceptions import SlowQLError, ParseError

    # Config
    config = Config()
    assert config

    # Engine
    engine = SlowQL(config=config)
    assert engine

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
    from slowql.analyzers.base import BaseAnalyzer, RuleBasedAnalyzer, PatternAnalyzer
    from slowql.analyzers.registry import AnalyzerRegistry

    # These are abstract, so we can't instantiate directly
    # But we can check they exist
    assert BaseAnalyzer
    assert RuleBasedAnalyzer
    assert PatternAnalyzer
    assert AnalyzerRegistry

def test_instantiate_rule_classes():
    from slowql.rules.base import Rule, PatternRule, ASTRule

    # Abstract classes
    assert Rule
    assert PatternRule
    assert ASTRule

def test_instantiate_parser_classes():
    from slowql.parser.base import BaseParser
    from slowql.parser.tokenizer import Tokenizer
    from slowql.parser.universal import UniversalParser

    # BaseParser is abstract
    assert BaseParser
    assert Tokenizer
    assert UniversalParser

def test_main_functions():
    from slowql import analyze, analyze_file

    # These are functions
    assert callable(analyze)
    assert callable(analyze_file)