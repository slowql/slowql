import pytest

from slowql.core.models import Location, Query
from slowql.rules.cost.bigquery import BigQueryMissingLimitRule, BigQuerySelectStarCostRule
from slowql.rules.cost.snowflake import (
    SnowflakeCopyIntoWithoutFileFormatRule,
    SnowflakeSelectStarCostRule,
)
from slowql.rules.performance.execution import ScalarUdfInQueryRule
from slowql.rules.performance.hints import IndexHintRule, QueryOptimizerHintRule
from slowql.rules.performance.indexing import IlikeOnIndexedColumnRule
from slowql.rules.performance.memory import UnboundedTempTableRule
from slowql.rules.quality.modern_sql import RownumWithoutOrderByRule, SelectFromDualRule
from slowql.rules.reliability.data_safety import InsertIgnoreRule, ReplaceIntoRule
from slowql.rules.security.command import OSCommandInjectionPostgresRule, OSCommandInjectionTsqlRule


@pytest.fixture
def loc():
    return Location(line=1, column=1)

@pytest.fixture
def mysql_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="mysql", location=loc)

@pytest.fixture
def pg_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="postgres", location=loc)

@pytest.fixture
def tsql_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="tsql", location=loc)

@pytest.fixture
def oracle_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="oracle", location=loc)

@pytest.fixture
def bq_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="bigquery", location=loc)

@pytest.fixture
def sf_query(loc):
    return lambda sql: Query(raw=sql, normalized=sql.upper(), dialect="snowflake", location=loc)

def test_mysql_specific_rules(mysql_query, pg_query):
    # InsertIgnoreRule
    rule = InsertIgnoreRule()
    assert len(rule.check(mysql_query("INSERT IGNORE INTO t (a) VALUES (1)"))) == 1
    assert len(rule.check(pg_query("INSERT INTO t (a) VALUES (1)"))) == 0  # Wrong dialect

    # ReplaceIntoRule
    rule = ReplaceIntoRule()
    assert len(rule.check(mysql_query("REPLACE INTO t (a) VALUES (1)"))) == 1
    assert len(rule.check(pg_query("INSERT INTO t (a) VALUES (1)"))) == 0

def test_postgres_specific_rules(pg_query, mysql_query):
    # IlikeOnIndexedColumnRule
    rule = IlikeOnIndexedColumnRule()
    assert len(rule.check(pg_query("SELECT * FROM t WHERE a ILIKE 'v%'"))) == 1
    assert len(rule.check(mysql_query("SELECT * FROM t WHERE a LIKE 'v%'"))) == 0

def test_oracle_specific_rules(oracle_query, pg_query):
    # RownumWithoutOrderByRule
    rule = RownumWithoutOrderByRule()
    assert len(rule.check(oracle_query("SELECT * FROM t WHERE ROWNUM <= 10"))) == 1
    assert len(rule.check(oracle_query("SELECT * FROM t WHERE ROWNUM <= 10 ORDER BY id"))) == 0
    assert len(rule.check(pg_query("SELECT * FROM t LIMIT 10"))) == 0

    # SelectFromDualRule
    rule = SelectFromDualRule()
    assert len(rule.check(oracle_query("SELECT 1 FROM DUAL"))) == 1
    assert len(rule.check(pg_query("SELECT 1"))) == 0

def test_bigquery_specific_rules(bq_query, pg_query):
    # BigQuerySelectStarCostRule
    rule = BigQuerySelectStarCostRule()
    assert len(rule.check(bq_query("SELECT * FROM t"))) == 1
    assert len(rule.check(pg_query("SELECT * FROM t"))) == 0

    # BigQueryMissingLimitRule
    rule = BigQueryMissingLimitRule()
    assert len(rule.check(bq_query("SELECT a FROM t"))) == 1
    assert len(rule.check(bq_query("SELECT a FROM t LIMIT 10"))) == 0

def test_snowflake_specific_rules(sf_query, pg_query):
    # SnowflakeSelectStarCostRule
    rule = SnowflakeSelectStarCostRule()
    assert len(rule.check(sf_query("SELECT * FROM t"))) == 1
    assert len(rule.check(pg_query("SELECT * FROM t"))) == 0

    # SnowflakeCopyIntoWithoutFileFormatRule
    rule = SnowflakeCopyIntoWithoutFileFormatRule()
    assert len(rule.check(sf_query("COPY INTO t FROM @s"))) == 1
    assert len(rule.check(sf_query("COPY INTO t FROM @s FILE_FORMAT = (TYPE = CSV)"))) == 0

def test_security_dialect_splitting(tsql_query, pg_query):
    # TSQL
    rule = OSCommandInjectionTsqlRule()
    assert len(rule.check(tsql_query("EXEC xp_cmdshell 'dir'"))) == 1
    assert len(rule.check(pg_query("SELECT pg_read_file('etc/passwd')"))) == 0

    # Postgres
    rule = OSCommandInjectionPostgresRule()
    assert len(rule.check(pg_query("SELECT pg_read_file('etc/passwd')"))) == 1
    assert len(rule.check(tsql_query("EXEC xp_cmdshell 'dir'"))) == 0

def test_existing_rules_dialect_guards(tsql_query, pg_query, mysql_query):
    # QueryOptimizerHintRule (tsql only)
    rule = QueryOptimizerHintRule()
    assert len(rule.check(tsql_query("SELECT * FROM t OPTION(HASH JOIN)"))) == 1
    assert len(rule.check(pg_query("SELECT * FROM t"))) == 0

    # ScalarUdfInQueryRule (tsql only)
    rule = ScalarUdfInQueryRule()
    assert len(rule.check(tsql_query("SELECT dbo.fn(a) FROM t"))) == 1
    assert len(rule.check(pg_query("SELECT fn(a) FROM t"))) == 0

    # UnboundedTempTableRule (tsql only)
    rule = UnboundedTempTableRule()
    assert len(rule.check(tsql_query("SELECT * INTO #t FROM s"))) == 1
    assert len(rule.check(pg_query("CREATE TEMP TABLE t AS SELECT * FROM s"))) == 0

    rule = IndexHintRule()
    assert len(rule.check(mysql_query("SELECT * FROM t USE INDEX (i)"))) == 1
    assert len(rule.check(tsql_query("SELECT * FROM t WITH(INDEX=i)"))) == 1
    assert len(rule.check(pg_query("SELECT * FROM t"))) == 0
