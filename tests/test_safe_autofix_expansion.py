"""Tests for new safe autofix implementations."""
from __future__ import annotations

import sqlglot

from slowql.core.autofixer import AutoFixer
from slowql.core.models import FixConfidence, Location, Query

_LOC = Location(line=1, column=1)


def _q(sql: str, dialect: str = "postgresql") -> Query:
    try:
        ast = sqlglot.parse_one(sql)
    except Exception:
        ast = None
    return Query(raw=sql, normalized=sql, dialect=dialect,
                 location=_LOC, query_type="SELECT", ast=ast)


class TestCaseWithoutElseAutofix:
    def test_adds_else_null(self) -> None:
        from slowql.rules.quality.null_handling import CaseWithoutElseRule
        rule = CaseWithoutElseRule()
        sql = "SELECT CASE WHEN status = 1 THEN 'active' END FROM users"
        fix = rule.suggest_fix(_q(sql))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert fix.is_safe is True
        assert fix.replacement == "ELSE NULL END"
        assert fix.original == "END"

    def test_result_is_correct(self) -> None:
        from slowql.rules.quality.null_handling import CaseWithoutElseRule
        rule = CaseWithoutElseRule()
        sql = "SELECT CASE WHEN status = 1 THEN 'active' END FROM users"
        fix = rule.suggest_fix(_q(sql))
        assert fix is not None
        result = AutoFixer().apply_fix(sql, fix)
        assert "ELSE NULL END" in result
        assert result == "SELECT CASE WHEN status = 1 THEN 'active' ELSE NULL END FROM users"

    def test_no_fix_when_else_exists(self) -> None:
        from slowql.rules.quality.null_handling import CaseWithoutElseRule
        rule = CaseWithoutElseRule()
        sql = "SELECT CASE WHEN x = 1 THEN 'a' ELSE 'b' END FROM t"
        fix = rule.suggest_fix(_q(sql))
        assert fix is None

    def test_no_fix_without_case(self) -> None:
        from slowql.rules.quality.null_handling import CaseWithoutElseRule
        rule = CaseWithoutElseRule()
        sql = "SELECT id FROM users"
        fix = rule.suggest_fix(_q(sql))
        assert fix is None

    def test_preview_diff(self) -> None:
        from slowql.rules.quality.null_handling import CaseWithoutElseRule
        rule = CaseWithoutElseRule()
        sql = "SELECT CASE WHEN status = 1 THEN 'active' END FROM users"
        fix = rule.suggest_fix(_q(sql))
        assert fix is not None
        diff = AutoFixer().preview_fixes(sql, [fix])
        assert "ELSE NULL END" in diff


class TestPgDoBlockAutofix:
    def test_adds_language_plpgsql(self) -> None:
        from slowql.rules.quality.style import PgDoBlockWithoutLanguageRule
        rule = PgDoBlockWithoutLanguageRule()
        sql = "DO $$ BEGIN RAISE NOTICE 'hi'; END $$;"
        fix = rule.suggest_fix(_q(sql))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert fix.is_safe is True
        assert "LANGUAGE plpgsql" in fix.replacement

    def test_result_contains_language(self) -> None:
        from slowql.rules.quality.style import PgDoBlockWithoutLanguageRule
        rule = PgDoBlockWithoutLanguageRule()
        sql = "DO $$ BEGIN RAISE NOTICE 'hi'; END $$;"
        fix = rule.suggest_fix(_q(sql))
        assert fix is not None
        result = sql.replace(fix.original, fix.replacement, 1)
        assert "LANGUAGE plpgsql" in result

    def test_no_fix_when_language_exists(self) -> None:
        from slowql.rules.quality.style import PgDoBlockWithoutLanguageRule
        rule = PgDoBlockWithoutLanguageRule()
        sql = "DO $$ BEGIN RAISE NOTICE 'hi'; END $$ LANGUAGE plpgsql;"
        fix = rule.suggest_fix(_q(sql))
        assert fix is None

    def test_no_fix_on_non_do_block(self) -> None:
        from slowql.rules.quality.style import PgDoBlockWithoutLanguageRule
        rule = PgDoBlockWithoutLanguageRule()
        sql = "SELECT 1 FROM users"
        fix = rule.suggest_fix(_q(sql))
        assert fix is None


class TestAutofixCount:
    def test_total_safe_autofixes(self) -> None:
        from slowql.rules.base import Rule
        from slowql.rules.catalog import get_all_rules

        rules = get_all_rules()
        count = sum(1 for r in rules if type(r).suggest_fix is not Rule.suggest_fix)
        assert count >= 11  # was 9, now 11
