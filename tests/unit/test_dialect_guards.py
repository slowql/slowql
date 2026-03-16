from __future__ import annotations

from slowql.core.models import Location, Query
from slowql.rules.performance.locking import ReadUncommittedHintRule
from slowql.rules.security.configuration import DangerousServerConfigRule


def _make_query(sql: str, dialect: str = "unknown") -> Query:
    return Query(
        raw=sql,
        normalized=sql.upper(),
        dialect=dialect,
        location=Location(line=1, column=1),
    )

# ── _dialect_matches logic ──────────────────────────────────────

def test_empty_dialects_always_matches():
    """Rule with no dialect restriction fires on all dialects."""
    # Temporarily test with empty dialects
    class UnrestrictedRule(ReadUncommittedHintRule):
        dialects = ()
    r = UnrestrictedRule()
    assert r._dialect_matches(_make_query("SELECT 1", "postgresql")) is True
    assert r._dialect_matches(_make_query("SELECT 1", "mysql")) is True
    assert r._dialect_matches(_make_query("SELECT 1", "unknown")) is True

def test_dialect_matches_correct_dialect():
    rule = ReadUncommittedHintRule()
    assert rule._dialect_matches(_make_query("SELECT 1", "tsql")) is True

def test_dialect_does_not_match_wrong_dialect():
    rule = ReadUncommittedHintRule()
    assert rule._dialect_matches(_make_query("SELECT 1", "postgresql")) is False
    assert rule._dialect_matches(_make_query("SELECT 1", "mysql")) is False

def test_unknown_dialect_always_matches():
    """When dialect is unknown, rules always fire (conservative)."""
    rule = ReadUncommittedHintRule()
    assert rule._dialect_matches(_make_query("SELECT 1", "unknown")) is True

def test_none_dialect_always_matches():
    rule = ReadUncommittedHintRule()
    q = _make_query("SELECT 1", "unknown")
    object.__setattr__(q, "dialect", None)
    assert rule._dialect_matches(q) is True

def test_empty_string_dialect_always_matches():
    rule = ReadUncommittedHintRule()
    q = _make_query("SELECT 1", "unknown")
    object.__setattr__(q, "dialect", "")
    assert rule._dialect_matches(q) is True

# ── end-to-end: rule skips on wrong dialect ──────────────────────

def test_nolock_rule_skips_on_postgresql():
    """ReadUncommittedHintRule must not fire on PostgreSQL queries."""
    rule = ReadUncommittedHintRule()
    q = _make_query("SELECT * FROM t WITH (NOLOCK)", "postgresql")
    assert rule.check(q) == []

def test_nolock_rule_fires_on_tsql():
    """ReadUncommittedHintRule fires when dialect is tsql."""
    rule = ReadUncommittedHintRule()
    q = _make_query("SELECT * FROM t WITH (NOLOCK)", "tsql")
    assert len(rule.check(q)) > 0

def test_nolock_rule_fires_on_unknown_dialect():
    """ReadUncommittedHintRule fires when dialect is unknown (conservative)."""
    rule = ReadUncommittedHintRule()
    q = _make_query("SELECT * FROM t WITH (NOLOCK)", "unknown")
    assert len(rule.check(q)) > 0

def test_sp_configure_rule_skips_on_postgresql():
    """DangerousServerConfigRule must not fire on PostgreSQL queries."""
    rule = DangerousServerConfigRule()
    q = _make_query("EXEC sp_configure 'xp_cmdshell', 1", "postgresql")
    assert rule.check(q) == []

def test_sp_configure_rule_fires_on_tsql():
    """DangerousServerConfigRule fires when dialect is tsql."""
    rule = DangerousServerConfigRule()
    q = _make_query("EXEC sp_configure 'xp_cmdshell', 1", "tsql")
    assert len(rule.check(q)) > 0

def test_sp_configure_rule_fires_on_unknown():
    """DangerousServerConfigRule fires on unknown dialect (conservative)."""
    rule = DangerousServerConfigRule()
    q = _make_query("EXEC sp_configure 'xp_cmdshell', 1", "unknown")
    assert len(rule.check(q)) > 0

# ── suggest_fix respects dialect guard ───────────────────────────

def test_nolock_fix_not_suggested_on_postgresql():
    """suggest_fix must return None when dialect guard blocks the rule."""
    rule = ReadUncommittedHintRule()
    q = _make_query("SELECT * FROM t WITH (NOLOCK)", "postgresql")
    assert rule.suggest_fix(q) is None

def test_nolock_fix_suggested_on_tsql():
    """suggest_fix returns a Fix when dialect matches."""
    rule = ReadUncommittedHintRule()
    q = _make_query("SELECT * FROM t WITH (NOLOCK)", "tsql")
    fix = rule.suggest_fix(q)
    assert fix is not None
