"""Tests for final dialect gap-fill rules."""
from __future__ import annotations

from slowql.core.models import Location, Query

_LOC = Location(line=1, column=1)


def _q(sql: str, dialect: str) -> Query:
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type="SELECT")


class TestPgSecurityDefinerRule:
    def test_fires(self) -> None:
        from slowql.rules.security.configuration import PgSecurityDefinerWithoutSearchPathRule
        assert len(PgSecurityDefinerWithoutSearchPathRule().check(_q("CREATE FUNCTION f() RETURNS void SECURITY DEFINER AS $$ BEGIN END $$;", "postgresql"))) > 0

    def test_no_fire_with_search_path(self) -> None:
        from slowql.rules.security.configuration import PgSecurityDefinerWithoutSearchPathRule
        assert PgSecurityDefinerWithoutSearchPathRule().check(_q("CREATE FUNCTION f() RETURNS void SECURITY DEFINER SET search_path = pg_catalog AS $$ BEGIN END $$;", "postgresql")) == []


class TestMysqlGroupByImplicitSortRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.modern_sql import MysqlGroupByImplicitSortRule
        assert len(MysqlGroupByImplicitSortRule().check(_q("SELECT dept, COUNT(*) FROM emp GROUP BY dept", "mysql"))) > 0

    def test_no_fire_with_order_by(self) -> None:
        from slowql.rules.quality.modern_sql import MysqlGroupByImplicitSortRule
        assert MysqlGroupByImplicitSortRule().check(_q("SELECT dept, COUNT(*) FROM emp GROUP BY dept ORDER BY dept", "mysql")) == []


class TestMysqlMyisamEngineRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.data_safety import MysqlMyisamEngineRule
        assert len(MysqlMyisamEngineRule().check(_q("CREATE TABLE t (id INT) ENGINE=MyISAM", "mysql"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.reliability.data_safety import MysqlMyisamEngineRule
        assert MysqlMyisamEngineRule().check(_q("CREATE TABLE t (id INT) ENGINE=MyISAM", "postgresql")) == []


class TestMysqlLockInShareModeRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.modern_sql import MysqlLockInShareModeRule
        assert len(MysqlLockInShareModeRule().check(_q("SELECT * FROM t WHERE id = 1 LOCK IN SHARE MODE", "mysql"))) > 0


class TestTsqlWaitforDelayRule:
    def test_fires(self) -> None:
        from slowql.rules.security.dos import TsqlWaitforDelayRule
        assert len(TsqlWaitforDelayRule().check(_q("WAITFOR DELAY '00:00:05'", "tsql"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.security.dos import TsqlWaitforDelayRule
        assert TsqlWaitforDelayRule().check(_q("WAITFOR DELAY '00:00:05'", "postgresql")) == []


class TestTsqlQuotedIdentifierOffRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.style import TsqlQuotedIdentifierOffRule
        assert len(TsqlQuotedIdentifierOffRule().check(_q("SET QUOTED_IDENTIFIER OFF", "tsql"))) > 0


class TestOracleAutonomousTransactionRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.transactions import OracleAutonomousTransactionRule
        assert len(OracleAutonomousTransactionRule().check(_q("PRAGMA AUTONOMOUS_TRANSACTION;", "oracle"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.reliability.transactions import OracleAutonomousTransactionRule
        assert OracleAutonomousTransactionRule().check(_q("PRAGMA AUTONOMOUS_TRANSACTION;", "postgresql")) == []


class TestSnowflakeCloneWithoutCopyGrantsRule:
    def test_fires(self) -> None:
        from slowql.rules.security.data_protection import SnowflakeCloneWithoutCopyGrantsRule
        assert len(SnowflakeCloneWithoutCopyGrantsRule().check(_q("CREATE TABLE t_clone CLONE t", "snowflake"))) > 0

    def test_no_fire_with_copy_grants(self) -> None:
        from slowql.rules.security.data_protection import SnowflakeCloneWithoutCopyGrantsRule
        assert SnowflakeCloneWithoutCopyGrantsRule().check(_q("CREATE TABLE t_clone CLONE t COPY GRANTS", "snowflake")) == []


class TestClickHouseMutationRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.clickhouse import ClickHouseMutationRule
        assert len(ClickHouseMutationRule().check(_q("ALTER TABLE t DELETE WHERE id = 1", "clickhouse"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.clickhouse import ClickHouseMutationRule
        assert ClickHouseMutationRule().check(_q("ALTER TABLE t DELETE WHERE id = 1", "postgresql")) == []


class TestSqliteForeignKeysOffRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.sqlite import SqliteForeignKeysOffRule
        assert len(SqliteForeignKeysOffRule().check(_q("PRAGMA foreign_keys = OFF", "sqlite"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.reliability.sqlite import SqliteForeignKeysOffRule
        assert SqliteForeignKeysOffRule().check(_q("PRAGMA foreign_keys = OFF", "postgresql")) == []


class TestSparkCacheTableRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.spark import SparkCacheTableWithoutFilterRule
        assert len(SparkCacheTableWithoutFilterRule().check(_q("CACHE TABLE big_events", "spark"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.cost.spark import SparkCacheTableWithoutFilterRule
        assert SparkCacheTableWithoutFilterRule().check(_q("CACHE TABLE big_events", "postgresql")) == []


class TestFinalCatalog:
    def test_total(self) -> None:
        from slowql.rules.catalog import get_all_rules
        assert len(get_all_rules()) == 272

    def test_no_duplicates(self) -> None:
        from collections import Counter

        from slowql.rules.catalog import get_all_rules
        dupes = {k: v for k, v in Counter(r.id for r in get_all_rules()).items() if v > 1}
        assert not dupes, f"Duplicates: {dupes}"
