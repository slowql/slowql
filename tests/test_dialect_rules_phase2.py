"""Tests for Phase 2 dialect-specific rules."""

from __future__ import annotations

from slowql.core.models import Location, Query

_LOC = Location(line=1, column=1)


def _q(sql: str, dialect: str) -> Query:
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type="SELECT")


class TestScalarUdfDialect:
    def test_fires_on_tsql(self) -> None:
        from slowql.rules.performance.execution import ScalarUdfInQueryRule
        assert ScalarUdfInQueryRule().dialects == ("tsql",)
        assert len(ScalarUdfInQueryRule().check(_q("SELECT dbo.GetName(id) FROM users", "tsql"))) > 0

    def test_skips_on_postgresql(self) -> None:
        from slowql.rules.performance.execution import ScalarUdfInQueryRule
        assert ScalarUdfInQueryRule().check(_q("SELECT dbo.GetName(id) FROM users", "postgresql")) == []


class TestPgSleepUsageRule:
    def test_fires_on_postgresql(self) -> None:
        from slowql.rules.security.dos import PgSleepUsageRule
        assert PgSleepUsageRule().dialects == ("postgresql",)
        assert len(PgSleepUsageRule().check(_q("SELECT pg_sleep(5)", "postgresql"))) > 0

    def test_skips_on_mysql(self) -> None:
        from slowql.rules.security.dos import PgSleepUsageRule
        assert PgSleepUsageRule().check(_q("SELECT pg_sleep(5)", "mysql")) == []

    def test_fires_on_postgres_alias(self) -> None:
        from slowql.rules.security.dos import PgSleepUsageRule
        assert len(PgSleepUsageRule().check(_q("SELECT pg_sleep(5)", "postgres"))) > 0


class TestSearchPathManipulationRule:
    def test_fires_on_postgresql(self) -> None:
        from slowql.rules.security.configuration import SearchPathManipulationRule
        assert SearchPathManipulationRule().dialects == ("postgresql",)
        assert len(SearchPathManipulationRule().check(_q("SET search_path TO evil, public", "postgresql"))) > 0

    def test_skips_on_mysql(self) -> None:
        from slowql.rules.security.configuration import SearchPathManipulationRule
        assert SearchPathManipulationRule().check(_q("SET search_path TO evil", "mysql")) == []


class TestSqlCalcFoundRowsRule:
    def test_fires_on_mysql(self) -> None:
        from slowql.rules.quality.modern_sql import SqlCalcFoundRowsRule
        assert SqlCalcFoundRowsRule().dialects == ("mysql",)
        assert len(SqlCalcFoundRowsRule().check(_q("SELECT SQL_CALC_FOUND_ROWS * FROM t LIMIT 10", "mysql"))) > 0

    def test_skips_on_postgresql(self) -> None:
        from slowql.rules.quality.modern_sql import SqlCalcFoundRowsRule
        assert SqlCalcFoundRowsRule().check(_q("SELECT SQL_CALC_FOUND_ROWS * FROM t", "postgresql")) == []


class TestUtf8InsteadOfUtf8mb4Rule:
    def test_fires_on_utf8(self) -> None:
        from slowql.rules.reliability.data_safety import Utf8InsteadOfUtf8mb4Rule
        assert Utf8InsteadOfUtf8mb4Rule().dialects == ("mysql",)
        assert len(Utf8InsteadOfUtf8mb4Rule().check(_q("CREATE TABLE t (c VARCHAR(50)) DEFAULT CHARSET=utf8", "mysql"))) > 0

    def test_no_fire_on_utf8mb4(self) -> None:
        from slowql.rules.reliability.data_safety import Utf8InsteadOfUtf8mb4Rule
        assert Utf8InsteadOfUtf8mb4Rule().check(_q("CREATE TABLE t (c VARCHAR(50)) DEFAULT CHARSET=utf8mb4", "mysql")) == []

    def test_skips_on_postgresql(self) -> None:
        from slowql.rules.reliability.data_safety import Utf8InsteadOfUtf8mb4Rule
        assert Utf8InsteadOfUtf8mb4Rule().check(_q("CREATE TABLE t (c VARCHAR(50)) DEFAULT CHARSET=utf8", "postgresql")) == []


class TestAtAtIdentityRule:
    def test_fires_on_tsql(self) -> None:
        from slowql.rules.reliability.data_safety import AtAtIdentityRule
        assert AtAtIdentityRule().dialects == ("tsql",)
        assert len(AtAtIdentityRule().check(_q("SELECT @@IDENTITY", "tsql"))) > 0

    def test_skips_on_postgresql(self) -> None:
        from slowql.rules.reliability.data_safety import AtAtIdentityRule
        assert AtAtIdentityRule().check(_q("SELECT @@IDENTITY", "postgresql")) == []


class TestMergeWithoutHoldlockRule:
    def test_fires_without_holdlock(self) -> None:
        from slowql.rules.reliability.race_conditions import MergeWithoutHoldlockRule
        assert MergeWithoutHoldlockRule().dialects == ("tsql",)
        sql = "MERGE INTO target USING source ON target.id = source.id WHEN NOT MATCHED THEN INSERT (id) VALUES (source.id);"
        assert len(MergeWithoutHoldlockRule().check(_q(sql, "tsql"))) > 0

    def test_no_fire_with_holdlock(self) -> None:
        from slowql.rules.reliability.race_conditions import MergeWithoutHoldlockRule
        sql = "MERGE INTO target WITH (HOLDLOCK) USING source ON target.id = source.id WHEN NOT MATCHED THEN INSERT (id) VALUES (source.id);"
        assert MergeWithoutHoldlockRule().check(_q(sql, "tsql")) == []

    def test_skips_on_postgresql(self) -> None:
        from slowql.rules.reliability.race_conditions import MergeWithoutHoldlockRule
        sql = "MERGE INTO target USING source ON target.id = source.id WHEN NOT MATCHED THEN INSERT (id) VALUES (source.id);"
        assert MergeWithoutHoldlockRule().check(_q(sql, "postgresql")) == []


class TestMissingSetNocountRule:
    def test_fires_without_nocount(self) -> None:
        from slowql.rules.performance.network import MissingSetNocountRule
        assert MissingSetNocountRule().dialects == ("tsql",)
        assert len(MissingSetNocountRule().check(_q("CREATE PROCEDURE dbo.MyProc AS BEGIN SELECT 1 END", "tsql"))) > 0

    def test_no_fire_with_nocount(self) -> None:
        from slowql.rules.performance.network import MissingSetNocountRule
        assert MissingSetNocountRule().check(_q("CREATE PROCEDURE dbo.MyProc AS BEGIN SET NOCOUNT ON; SELECT 1 END", "tsql")) == []

    def test_skips_on_postgresql(self) -> None:
        from slowql.rules.performance.network import MissingSetNocountRule
        assert MissingSetNocountRule().check(_q("CREATE PROCEDURE dbo.MyProc AS BEGIN SELECT 1 END", "postgresql")) == []


class TestOracleUtlAccessRule:
    def test_fires_on_utl_http(self) -> None:
        from slowql.rules.security.command import OracleUtlAccessRule
        assert OracleUtlAccessRule().dialects == ("oracle",)
        assert len(OracleUtlAccessRule().check(_q("SELECT UTL_HTTP.REQUEST('http://evil.com') FROM dual", "oracle"))) > 0

    def test_skips_on_postgresql(self) -> None:
        from slowql.rules.security.command import OracleUtlAccessRule
        assert OracleUtlAccessRule().check(_q("SELECT UTL_HTTP.REQUEST('http://evil.com') FROM dual", "postgresql")) == []


class TestConnectByWithoutNocycleRule:
    def test_fires_without_nocycle(self) -> None:
        from slowql.rules.reliability.timeouts import ConnectByWithoutNocycleRule
        assert ConnectByWithoutNocycleRule().dialects == ("oracle",)
        assert len(ConnectByWithoutNocycleRule().check(_q("SELECT * FROM emp CONNECT BY PRIOR emp_id = mgr_id", "oracle"))) > 0

    def test_no_fire_with_nocycle(self) -> None:
        from slowql.rules.reliability.timeouts import ConnectByWithoutNocycleRule
        assert ConnectByWithoutNocycleRule().check(_q("SELECT * FROM emp CONNECT BY NOCYCLE PRIOR emp_id = mgr_id", "oracle")) == []

    def test_skips_on_postgresql(self) -> None:
        from slowql.rules.reliability.timeouts import ConnectByWithoutNocycleRule
        assert ConnectByWithoutNocycleRule().check(_q("SELECT * FROM emp CONNECT BY PRIOR emp_id = mgr_id", "postgresql")) == []
