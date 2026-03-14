from slowql.core.models import FixConfidence
from slowql.parser.universal import UniversalParser
from slowql.rules.performance.locking import ReadUncommittedHintRule

parser = UniversalParser()

def _parse(sql):
    return parser.parse(sql)[0]

def test_fires_on_nolock():
    q = _parse("SELECT * FROM t WITH (NOLOCK)")
    fix = ReadUncommittedHintRule().suggest_fix(q)
    assert fix is not None
    assert fix.replacement == ""
    assert "WITH (NOLOCK)" in fix.original or "with (nolock)" in fix.original.lower()
    assert fix.is_safe is True
    assert fix.confidence == FixConfidence.SAFE

def test_fires_on_readuncommitted_hint():
    q = _parse("SELECT * FROM t WITH (READUNCOMMITTED)")
    fix = ReadUncommittedHintRule().suggest_fix(q)
    assert fix is not None
    assert fix.replacement == ""
    assert fix.is_safe is True
    assert fix.confidence == FixConfidence.SAFE

def test_result_has_hint_removed():
    sql = "SELECT * FROM t WITH (NOLOCK)"
    q = _parse(sql)
    fix = ReadUncommittedHintRule().suggest_fix(q)
    assert fix is not None
    result = sql.replace(fix.original, fix.replacement, 1)
    assert "NOLOCK" not in result.upper()
    assert "SELECT * FROM t" in result

def test_does_not_fire_on_read_uncommitted_bare():
    q = _parse("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")
    fix = ReadUncommittedHintRule().suggest_fix(q)
    assert fix is None

def test_does_not_fire_on_clean_query():
    q = _parse("SELECT * FROM t WHERE id = 1")
    fix = ReadUncommittedHintRule().suggest_fix(q)
    assert fix is None
