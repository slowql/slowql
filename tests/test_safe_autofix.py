"""Tests for safe autofix suggest_fix() implementations."""
from __future__ import annotations

import sqlglot

from slowql.core.models import FixConfidence, Location, Query

_LOC = Location(line=1, column=1)


def _q(sql: str, dialect: str) -> Query:
    try:
        ast = sqlglot.parse_one(sql)
    except Exception:
        ast = None
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type="SELECT", ast=ast)


class TestNullComparisonAutofix:
    def test_eq_null(self) -> None:
        from slowql.rules.quality.null_handling import NullComparisonRule
        fix = NullComparisonRule().suggest_fix(_q("SELECT * FROM t WHERE x = NULL", "postgresql"))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert "IS NULL" in fix.replacement
        assert "= NULL" in fix.original or "=NULL" in fix.original

    def test_neq_null(self) -> None:
        from slowql.rules.quality.null_handling import NullComparisonRule
        fix = NullComparisonRule().suggest_fix(_q("SELECT * FROM t WHERE x != NULL", "postgresql"))
        assert fix is not None
        assert "IS NOT NULL" in fix.replacement

    def test_no_fix_when_correct(self) -> None:
        from slowql.rules.quality.null_handling import NullComparisonRule
        fix = NullComparisonRule().suggest_fix(_q("SELECT * FROM t WHERE x IS NULL", "postgresql"))
        assert fix is None


class TestWildcardInExistsAutofix:
    def test_select_star_to_one(self) -> None:
        from slowql.rules.quality.style import WildcardInColumnListRule
        fix = WildcardInColumnListRule().suggest_fix(_q("SELECT * FROM t WHERE EXISTS (SELECT * FROM s)", "postgresql"))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert "SELECT 1" in fix.replacement
        assert "SELECT *" in fix.original

    def test_no_fix_when_correct(self) -> None:
        from slowql.rules.quality.style import WildcardInColumnListRule
        fix = WildcardInColumnListRule().suggest_fix(_q("SELECT * FROM t WHERE EXISTS (SELECT 1 FROM s)", "postgresql"))
        assert fix is None


class TestSelectFromDualAutofix:
    def test_removes_from_dual(self) -> None:
        from slowql.rules.quality.modern_sql import SelectFromDualRule
        fix = SelectFromDualRule().suggest_fix(_q("SELECT 1 FROM DUAL", "oracle"))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert fix.replacement == ""
        assert "FROM DUAL" in fix.original.upper()


class TestSqlCalcFoundRowsAutofix:
    def test_removes_keyword(self) -> None:
        from slowql.rules.quality.modern_sql import SqlCalcFoundRowsRule
        fix = SqlCalcFoundRowsRule().suggest_fix(_q("SELECT SQL_CALC_FOUND_ROWS * FROM t LIMIT 10", "mysql"))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert fix.replacement == ""
        assert "SQL_CALC_FOUND_ROWS" in fix.original


class TestLockInShareModeAutofix:
    def test_replaces_with_for_share(self) -> None:
        from slowql.rules.quality.modern_sql import MysqlLockInShareModeRule
        fix = MysqlLockInShareModeRule().suggest_fix(_q("SELECT * FROM t WHERE id = 1 LOCK IN SHARE MODE", "mysql"))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert fix.replacement == "FOR SHARE"


class TestAnsiNullsOffAutofix:
    def test_replaces_off_with_on(self) -> None:
        from slowql.rules.quality.style import AnsiNullsOffRule
        fix = AnsiNullsOffRule().suggest_fix(_q("SET ANSI_NULLS OFF", "tsql"))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert fix.replacement == "SET ANSI_NULLS ON"

    def test_no_fix_when_on(self) -> None:
        from slowql.rules.quality.style import AnsiNullsOffRule
        fix = AnsiNullsOffRule().suggest_fix(_q("SET ANSI_NULLS ON", "tsql"))
        assert fix is None


class TestQuotedIdentifierOffAutofix:
    def test_replaces_off_with_on(self) -> None:
        from slowql.rules.quality.style import TsqlQuotedIdentifierOffRule
        fix = TsqlQuotedIdentifierOffRule().suggest_fix(_q("SET QUOTED_IDENTIFIER OFF", "tsql"))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert fix.replacement == "SET QUOTED_IDENTIFIER ON"


class TestDuckDBOldStyleCastAutofix:
    def test_replaces_with_cast(self) -> None:
        from slowql.rules.quality.duckdb import DuckDBOldStyleCastRule
        fix = DuckDBOldStyleCastRule().suggest_fix(_q("SELECT INTEGER(col) FROM t", "duckdb"))
        assert fix is not None
        assert fix.confidence == FixConfidence.SAFE
        assert "CAST" in fix.replacement
        assert "INTEGER" in fix.replacement


class TestAutofixEndToEnd:
    """Test that AutoFixer can apply the fixes."""

    def test_apply_null_fix(self) -> None:
        from slowql.core.autofixer import AutoFixer
        from slowql.rules.quality.null_handling import NullComparisonRule

        sql = "SELECT * FROM t WHERE x = NULL"
        q = _q(sql, "postgresql")
        fix = NullComparisonRule().suggest_fix(q)
        assert fix is not None

        result = AutoFixer().apply_fix(sql, fix)
        assert "IS NULL" in result
        assert "= NULL" not in result

    def test_apply_ansi_nulls_fix(self) -> None:
        from slowql.core.autofixer import AutoFixer
        from slowql.rules.quality.style import AnsiNullsOffRule

        sql = "SET ANSI_NULLS OFF"
        q = _q(sql, "tsql")
        fix = AnsiNullsOffRule().suggest_fix(q)
        assert fix is not None

        result = AutoFixer().apply_fix(sql, fix)
        assert result == "SET ANSI_NULLS ON"

    def test_preview_diff(self) -> None:
        from slowql.core.autofixer import AutoFixer
        from slowql.rules.quality.style import AnsiNullsOffRule

        sql = "SET ANSI_NULLS OFF"
        q = _q(sql, "tsql")
        fix = AnsiNullsOffRule().suggest_fix(q)
        assert fix is not None

        diff = AutoFixer().preview_fixes(sql, [fix])
        assert "SET ANSI_NULLS ON" in diff
        assert "SET ANSI_NULLS OFF" in diff
