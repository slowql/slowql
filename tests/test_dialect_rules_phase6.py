"""Tests for Phase 6: Gap-fill rules."""
from __future__ import annotations

from slowql.core.models import Location, Query

_LOC = Location(line=1, column=1)


def _q(sql: str, dialect: str, query_type: str = "SELECT") -> Query:
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type=query_type)


class TestMysqlQueryCachePollutionRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.compute import MysqlQueryCachePollutionRule
        assert len(MysqlQueryCachePollutionRule().check(_q("SELECT id, COUNT(*) FROM t GROUP BY id", "mysql"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.cost.compute import MysqlQueryCachePollutionRule
        assert MysqlQueryCachePollutionRule().check(_q("SELECT id, COUNT(*) FROM t GROUP BY id", "postgresql")) == []


class TestTsqlCursorWithoutFastForwardRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.compute import TsqlCursorWithoutFastForwardRule
        assert len(TsqlCursorWithoutFastForwardRule().check(_q("DECLARE my_cur CURSOR FOR SELECT id FROM t", "tsql"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.cost.compute import TsqlCursorWithoutFastForwardRule
        assert TsqlCursorWithoutFastForwardRule().check(_q("DECLARE my_cur CURSOR FOR SELECT id FROM t", "postgresql")) == []


class TestOracleFullTableHintRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.compute import OracleFullTableHintRule
        assert len(OracleFullTableHintRule().check(_q("SELECT /*+ FULL(t) */ * FROM t", "oracle"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.cost.compute import OracleFullTableHintRule
        assert OracleFullTableHintRule().check(_q("SELECT /*+ FULL(t) */ * FROM t", "postgresql")) == []


class TestPgDoBlockWithoutLanguageRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.style import PgDoBlockWithoutLanguageRule
        assert len(PgDoBlockWithoutLanguageRule().check(_q("DO $$ BEGIN RAISE NOTICE 'hi'; END $$;", "postgresql"))) > 0

    def test_skips_mysql(self) -> None:
        from slowql.rules.quality.style import PgDoBlockWithoutLanguageRule
        assert PgDoBlockWithoutLanguageRule().check(_q("DO $$ BEGIN RAISE NOTICE 'hi'; END $$;", "mysql")) == []


class TestRedshiftDiststyleAllRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.style import RedshiftDiststyleAllRule
        assert len(RedshiftDiststyleAllRule().check(_q("CREATE TABLE t (id INT) DISTSTYLE ALL", "redshift"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.quality.style import RedshiftDiststyleAllRule
        assert RedshiftDiststyleAllRule().check(_q("CREATE TABLE t (id INT) DISTSTYLE ALL", "postgresql")) == []


class TestClickHouseOrderByWithoutLimitRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.style import ClickHouseOrderByWithoutLimitRule
        assert len(ClickHouseOrderByWithoutLimitRule().check(_q("SELECT * FROM t ORDER BY id", "clickhouse"))) > 0

    def test_no_fire_with_limit(self) -> None:
        from slowql.rules.quality.style import ClickHouseOrderByWithoutLimitRule
        assert ClickHouseOrderByWithoutLimitRule().check(_q("SELECT * FROM t ORDER BY id LIMIT 10", "clickhouse")) == []


class TestSnowflakeFlattenWithoutPathRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.style import SnowflakeFlattenWithoutPathRule
        assert len(SnowflakeFlattenWithoutPathRule().check(_q("SELECT * FROM t, LATERAL FLATTEN(col)", "snowflake"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.quality.style import SnowflakeFlattenWithoutPathRule
        assert SnowflakeFlattenWithoutPathRule().check(_q("SELECT * FROM t, LATERAL FLATTEN(col)", "postgresql")) == []


class TestRedshiftCopyWithCredentialsRule:
    def test_fires(self) -> None:
        from slowql.rules.security.data_protection import RedshiftCopyWithCredentialsRule
        assert len(RedshiftCopyWithCredentialsRule().check(_q("COPY t FROM 's3://b/d' ACCESS_KEY_ID 'AK' SECRET_ACCESS_KEY 'SK'", "redshift"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.security.data_protection import RedshiftCopyWithCredentialsRule
        assert RedshiftCopyWithCredentialsRule().check(_q("COPY t FROM 's3://b/d' ACCESS_KEY_ID 'AK'", "postgresql")) == []


class TestClickHouseUrlFunctionRule:
    def test_fires(self) -> None:
        from slowql.rules.security.command import ClickHouseUrlFunctionRule
        assert len(ClickHouseUrlFunctionRule().check(_q("SELECT * FROM url('http://internal:8080/data', CSV, 'id UInt32')", "clickhouse"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.security.command import ClickHouseUrlFunctionRule
        assert ClickHouseUrlFunctionRule().check(_q("SELECT * FROM url('http://internal:8080/data', CSV)", "postgresql")) == []


class TestSnowflakeCopyWithCredentialsRule:
    def test_fires(self) -> None:
        from slowql.rules.security.data_protection import SnowflakeCopyWithCredentialsRule
        assert len(SnowflakeCopyWithCredentialsRule().check(_q("COPY INTO t FROM @s CREDENTIALS=(AWS_KEY_ID='x' AWS_SECRET_KEY='y')", "snowflake"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.security.data_protection import SnowflakeCopyWithCredentialsRule
        assert SnowflakeCopyWithCredentialsRule().check(_q("COPY INTO t FROM @s CREDENTIALS=(AWS_KEY_ID='x')", "postgresql")) == []


class TestPhase6Catalog:
    def test_all_in_catalog(self) -> None:
        from slowql.rules.catalog import get_all_rules
        ids = {r.id for r in get_all_rules()}
        for eid in ["COST-MYSQL-001", "COST-TSQL-001", "COST-ORA-001", "QUAL-PG-001",
                     "QUAL-RS-001", "QUAL-CH-001", "QUAL-SF-001",
                     "SEC-RS-001", "SEC-CH-001", "SEC-SF-001"]:
            assert eid in ids, f"{eid} missing"

    def test_total(self) -> None:
        from slowql.rules.catalog import get_all_rules
        assert len(get_all_rules()) == 256

    def test_no_duplicates(self) -> None:
        from collections import Counter

        from slowql.rules.catalog import get_all_rules
        dupes = {k: v for k, v in Counter(r.id for r in get_all_rules()).items() if v > 1}
        assert not dupes, f"Duplicates: {dupes}"
