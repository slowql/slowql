"""Tests for Phase 3 dialect-specific rules."""
from __future__ import annotations

from slowql.core.models import Location, Query

_LOC = Location(line=1, column=1)


def _q(sql: str, dialect: str, query_type: str = "SELECT") -> Query:
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type=query_type)


class TestCountStarWithoutWhereRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.scanning import CountStarWithoutWhereRule
        assert len(CountStarWithoutWhereRule().check(_q("SELECT COUNT(*) FROM users", "postgresql"))) > 0

    def test_no_fire_with_where(self) -> None:
        from slowql.rules.performance.scanning import CountStarWithoutWhereRule
        assert CountStarWithoutWhereRule().check(_q("SELECT COUNT(*) FROM users WHERE active = true", "postgresql")) == []

    def test_skips_mysql(self) -> None:
        from slowql.rules.performance.scanning import CountStarWithoutWhereRule
        assert CountStarWithoutWhereRule().check(_q("SELECT COUNT(*) FROM users", "mysql")) == []


class TestNotInNullableSubqueryRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.scanning import NotInNullableSubqueryRule
        assert len(NotInNullableSubqueryRule().check(_q("SELECT * FROM a WHERE id NOT IN (SELECT id FROM b)", "postgresql"))) > 0

    def test_skips_mysql(self) -> None:
        from slowql.rules.performance.scanning import NotInNullableSubqueryRule
        assert NotInNullableSubqueryRule().check(_q("SELECT * FROM a WHERE id NOT IN (SELECT id FROM b)", "mysql")) == []


class TestSelectForUpdateWithoutNowaitPgRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.scanning import SelectForUpdateWithoutNowaitPgRule
        assert len(SelectForUpdateWithoutNowaitPgRule().check(_q("SELECT * FROM t FOR UPDATE", "postgresql"))) > 0

    def test_no_fire_with_nowait(self) -> None:
        from slowql.rules.performance.scanning import SelectForUpdateWithoutNowaitPgRule
        assert SelectForUpdateWithoutNowaitPgRule().check(_q("SELECT * FROM t FOR UPDATE NOWAIT", "postgresql")) == []


class TestCreateIndexWithoutConcurrentlyRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.data_safety import CreateIndexWithoutConcurrentlyRule
        assert len(CreateIndexWithoutConcurrentlyRule().check(_q("CREATE INDEX idx_name ON users(name)", "postgresql"))) > 0

    def test_no_fire(self) -> None:
        from slowql.rules.reliability.data_safety import CreateIndexWithoutConcurrentlyRule
        assert CreateIndexWithoutConcurrentlyRule().check(_q("CREATE INDEX CONCURRENTLY idx_name ON users(name)", "postgresql")) == []


class TestAlterTableVolatileDefault:
    def test_fires_on_now(self) -> None:
        from slowql.rules.reliability.data_safety import AlterTableAddColumnVolatileDefaultRule
        assert len(AlterTableAddColumnVolatileDefaultRule().check(_q("ALTER TABLE t ADD COLUMN created_at TIMESTAMP DEFAULT NOW()", "postgresql"))) > 0

    def test_no_fire_static(self) -> None:
        from slowql.rules.reliability.data_safety import AlterTableAddColumnVolatileDefaultRule
        assert AlterTableAddColumnVolatileDefaultRule().check(_q("ALTER TABLE t ADD COLUMN status INT DEFAULT 0", "postgresql")) == []


class TestRaiseNoticeInjectionRule:
    def test_fires(self) -> None:
        from slowql.rules.security.injection import RaiseNoticeInjectionRule
        assert len(RaiseNoticeInjectionRule().check(_q("RAISE NOTICE 'user: ' || user_input", "postgresql"))) > 0

    def test_skips_mysql(self) -> None:
        from slowql.rules.security.injection import RaiseNoticeInjectionRule
        assert RaiseNoticeInjectionRule().check(_q("RAISE NOTICE 'user: ' || user_input", "mysql")) == []


class TestLoadDataLocalInfileRule:
    def test_fires(self) -> None:
        from slowql.rules.security.data_protection import LoadDataLocalInfileRule
        assert len(LoadDataLocalInfileRule().check(_q("LOAD DATA LOCAL INFILE '/tmp/data.csv' INTO TABLE t", "mysql"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.security.data_protection import LoadDataLocalInfileRule
        assert LoadDataLocalInfileRule().check(_q("LOAD DATA LOCAL INFILE '/tmp/data.csv' INTO TABLE t", "postgresql")) == []


class TestOrderByRandRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.scanning import OrderByRandRule
        assert len(OrderByRandRule().check(_q("SELECT * FROM t ORDER BY RAND() LIMIT 1", "mysql"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.scanning import OrderByRandRule
        assert OrderByRandRule().check(_q("SELECT * FROM t ORDER BY RAND() LIMIT 1", "postgresql")) == []


class TestStraightJoinHintRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.style import StraightJoinHintRule
        assert len(StraightJoinHintRule().check(_q("SELECT STRAIGHT_JOIN * FROM a JOIN b ON a.id = b.id", "mysql"))) > 0


class TestOnUpdateCascadeTimestampRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.foreign_keys import OnUpdateCascadeTimestampRule
        assert len(OnUpdateCascadeTimestampRule().check(_q("CREATE TABLE t (id INT REFERENCES p(id) ON UPDATE CASCADE)", "mysql"))) > 0


class TestOpenRowsetRule:
    def test_fires(self) -> None:
        from slowql.rules.security.command import OpenRowsetRule
        assert len(OpenRowsetRule().check(_q("SELECT * FROM OPENROWSET('SQLNCLI', 'srv', 'q')", "tsql"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.security.command import OpenRowsetRule
        assert OpenRowsetRule().check(_q("SELECT * FROM OPENROWSET('SQLNCLI', 'srv', 'q')", "postgresql")) == []


class TestSpOACreateRule:
    def test_fires(self) -> None:
        from slowql.rules.security.command import SpOACreateRule
        assert len(SpOACreateRule().check(_q("EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUT", "tsql"))) > 0


class TestSelectIntoTempRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.memory import SelectIntoTempWithoutIndexRule
        assert len(SelectIntoTempWithoutIndexRule().check(_q("SELECT col1 INTO #temp FROM big_table", "tsql"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.memory import SelectIntoTempWithoutIndexRule
        assert SelectIntoTempWithoutIndexRule().check(_q("SELECT col1 INTO #temp FROM big_table", "postgresql")) == []


class TestTruncateInTryWithoutCatchRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.data_safety import TruncateInTryWithoutCatchRule
        assert len(TruncateInTryWithoutCatchRule().check(_q("BEGIN TRY TRUNCATE TABLE t END TRY", "tsql"))) > 0

    def test_no_fire_with_catch(self) -> None:
        from slowql.rules.reliability.data_safety import TruncateInTryWithoutCatchRule
        assert TruncateInTryWithoutCatchRule().check(_q("BEGIN TRY TRUNCATE TABLE t END TRY BEGIN CATCH THROW END CATCH", "tsql")) == []


class TestAnsiNullsOffRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.style import AnsiNullsOffRule
        assert len(AnsiNullsOffRule().check(_q("SET ANSI_NULLS OFF", "tsql"))) > 0


class TestOracleForUpdateWithoutNowaitRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.locking import OracleForUpdateWithoutNowaitRule
        assert len(OracleForUpdateWithoutNowaitRule().check(_q("SELECT * FROM t FOR UPDATE", "oracle"))) > 0

    def test_no_fire_nowait(self) -> None:
        from slowql.rules.performance.locking import OracleForUpdateWithoutNowaitRule
        assert OracleForUpdateWithoutNowaitRule().check(_q("SELECT * FROM t FOR UPDATE NOWAIT", "oracle")) == []


class TestOracleDbmsSqlInjectionRule:
    def test_fires(self) -> None:
        from slowql.rules.security.injection import OracleDbmsSqlInjectionRule
        assert len(OracleDbmsSqlInjectionRule().check(_q("DBMS_SQL.PARSE(cur, sql_str, DBMS_SQL.NATIVE)", "oracle"))) > 0


class TestOracleExecuteImmediateConcatRule:
    def test_fires(self) -> None:
        from slowql.rules.security.injection import OracleExecuteImmediateConcatRule
        assert len(OracleExecuteImmediateConcatRule().check(_q("EXECUTE IMMEDIATE 'SELECT * FROM ' || tbl", "oracle"))) > 0


class TestOracleAlterTableMoveRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.data_safety import OracleAlterTableMoveWithoutRebuildRule
        assert len(OracleAlterTableMoveWithoutRebuildRule().check(_q("ALTER TABLE t MOVE TABLESPACE new_ts", "oracle"))) > 0

    def test_no_fire_with_rebuild(self) -> None:
        from slowql.rules.reliability.data_safety import OracleAlterTableMoveWithoutRebuildRule
        assert OracleAlterTableMoveWithoutRebuildRule().check(_q("ALTER TABLE t MOVE TABLESPACE new_ts; ALTER INDEX idx REBUILD", "oracle")) == []


class TestOracleNvlInWhereRule:
    def test_fires(self) -> None:
        from slowql.rules.quality.modern_sql import OracleNvlInWhereRule
        assert len(OracleNvlInWhereRule().check(_q("SELECT * FROM t WHERE NVL(status, 0) = 1", "oracle"))) > 0


class TestSnowflakeCopyWithoutOnErrorRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.snowflake import SnowflakeCopyWithoutOnErrorRule
        assert len(SnowflakeCopyWithoutOnErrorRule().check(_q("COPY INTO my_table FROM @stage", "snowflake"))) > 0

    def test_no_fire(self) -> None:
        from slowql.rules.cost.snowflake import SnowflakeCopyWithoutOnErrorRule
        assert SnowflakeCopyWithoutOnErrorRule().check(_q("COPY INTO my_table FROM @stage ON_ERROR = 'CONTINUE'", "snowflake")) == []


class TestSnowflakeVariantInWhereRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.snowflake import SnowflakeVariantInWhereRule
        assert len(SnowflakeVariantInWhereRule().check(_q("SELECT * FROM t WHERE data:name = 'foo'", "snowflake"))) > 0


class TestSnowflakeWarehouseSizeHintRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.compute import SnowflakeWarehouseSizeHintRule
        assert len(SnowflakeWarehouseSizeHintRule().check(_q("SELECT * FROM t, LATERAL FLATTEN(input => arr)", "snowflake"))) > 0


class TestBigQueryDistinctOnUnnestRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.scanning import BigQueryDistinctOnUnnestRule
        assert len(BigQueryDistinctOnUnnestRule().check(_q("SELECT DISTINCT val FROM t, UNNEST(arr) AS val", "bigquery"))) > 0


class TestBigQueryRepeatedSubqueryRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.bigquery import BigQueryRepeatedSubqueryRule
        sql = "SELECT * FROM (SELECT id FROM t) a JOIN (SELECT id FROM t) b ON a.id = b.id"
        assert len(BigQueryRepeatedSubqueryRule().check(_q(sql, "bigquery"))) > 0

    def test_no_fire_with_cte(self) -> None:
        from slowql.rules.cost.bigquery import BigQueryRepeatedSubqueryRule
        sql = "WITH cte AS (SELECT id FROM t) SELECT * FROM cte a JOIN cte b ON a.id = b.id"
        assert BigQueryRepeatedSubqueryRule().check(_q(sql, "bigquery")) == []


class TestBigQueryDmlWithoutWhereRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.data_safety import BigQueryDmlWithoutWhereOnPartitionedRule
        assert len(BigQueryDmlWithoutWhereOnPartitionedRule().check(_q("DELETE FROM dataset.table", "bigquery", "DELETE"))) > 0

    def test_no_fire_with_where(self) -> None:
        from slowql.rules.reliability.data_safety import BigQueryDmlWithoutWhereOnPartitionedRule
        assert BigQueryDmlWithoutWhereOnPartitionedRule().check(_q("DELETE FROM t WHERE dt = '2024-01-01'", "bigquery", "DELETE")) == []


class TestPhase3Catalog:
    def test_all_in_catalog(self) -> None:
        from slowql.rules.catalog import get_all_rules
        ids = {r.id for r in get_all_rules()}
        expected = [
            "PERF-PG-002", "PERF-PG-003", "PERF-PG-004", "REL-PG-001", "REL-PG-002", "SEC-PG-003",
            "SEC-MYSQL-001", "PERF-MYSQL-001", "PERF-MYSQL-002", "PERF-MYSQL-003", "QUAL-MYSQL-002", "REL-MYSQL-004",
            "SEC-TSQL-001", "SEC-TSQL-002", "PERF-TSQL-002", "PERF-TSQL-003", "REL-TSQL-003", "QUAL-TSQL-001",
            "PERF-ORA-001", "SEC-ORA-002", "SEC-ORA-003", "REL-ORA-002", "QUAL-ORA-003",
            "REL-SF-001", "PERF-SF-001", "PERF-SF-002", "COST-SF-003",
            "PERF-BQ-001", "PERF-BQ-002", "COST-BQ-003", "REL-BQ-001",
        ]
        for eid in expected:
            assert eid in ids, f"{eid} missing"

    def test_total_count(self) -> None:
        from slowql.rules.catalog import get_all_rules
        assert len(get_all_rules()) == 256
