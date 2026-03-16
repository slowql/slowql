"""Tests for Phase 4: SQLite + Redshift dialect-specific rules."""
from __future__ import annotations

from slowql.core.models import Location, Query

_LOC = Location(line=1, column=1)


def _q(sql: str, dialect: str, query_type: str = "SELECT") -> Query:
    return Query(raw=sql, normalized=sql, dialect=dialect, location=_LOC, query_type=query_type)


# ── SQLite ───────────────────────────────────────────────────────────


class TestAttachDatabaseRule:
    def test_fires(self) -> None:
        from slowql.rules.security.sqlite import AttachDatabaseRule
        assert len(AttachDatabaseRule().check(_q("ATTACH DATABASE '/etc/passwd' AS stolen", "sqlite"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.security.sqlite import AttachDatabaseRule
        assert AttachDatabaseRule().check(_q("ATTACH DATABASE '/etc/passwd' AS stolen", "postgresql")) == []


class TestSqliteWalModeRule:
    def test_fires_on_delete_mode(self) -> None:
        from slowql.rules.performance.sqlite import SqliteWalModeRule
        assert len(SqliteWalModeRule().check(_q("PRAGMA journal_mode=delete", "sqlite"))) > 0

    def test_no_fire_on_wal(self) -> None:
        from slowql.rules.performance.sqlite import SqliteWalModeRule
        assert SqliteWalModeRule().check(_q("PRAGMA journal_mode=wal", "sqlite")) == []

    def test_skips_mysql(self) -> None:
        from slowql.rules.performance.sqlite import SqliteWalModeRule
        assert SqliteWalModeRule().check(_q("PRAGMA journal_mode=delete", "mysql")) == []


class TestLikeWithoutCollateNocaseRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.sqlite import LikeWithoutCollateNocaseRule
        assert len(LikeWithoutCollateNocaseRule().check(_q("SELECT * FROM t WHERE name LIKE '%foo%'", "sqlite"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.sqlite import LikeWithoutCollateNocaseRule
        assert LikeWithoutCollateNocaseRule().check(_q("SELECT * FROM t WHERE name LIKE '%foo%'", "postgresql")) == []


class TestSqliteAutoIncrementRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.sqlite import SqliteAutoIncrementRule
        assert len(SqliteAutoIncrementRule().check(_q("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT)", "sqlite"))) > 0

    def test_skips_mysql(self) -> None:
        from slowql.rules.performance.sqlite import SqliteAutoIncrementRule
        assert SqliteAutoIncrementRule().check(_q("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT)", "mysql")) == []


class TestSqliteDropColumnRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.sqlite import SqliteDropColumnRule
        assert len(SqliteDropColumnRule().check(_q("ALTER TABLE t DROP COLUMN old_col", "sqlite"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.reliability.sqlite import SqliteDropColumnRule
        assert SqliteDropColumnRule().check(_q("ALTER TABLE t DROP COLUMN old_col", "postgresql")) == []


# ── Redshift ─────────────────────────────────────────────────────────


class TestRedshiftSelectStarRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.redshift import RedshiftSelectStarRule
        assert len(RedshiftSelectStarRule().check(_q("SELECT * FROM big_table", "redshift"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.redshift import RedshiftSelectStarRule
        assert RedshiftSelectStarRule().check(_q("SELECT * FROM big_table", "postgresql")) == []


class TestOrderByWithoutLimitRedshiftRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.redshift import OrderByWithoutLimitRedshiftRule
        assert len(OrderByWithoutLimitRedshiftRule().check(_q("SELECT id FROM t ORDER BY id", "redshift"))) > 0

    def test_no_fire_with_limit(self) -> None:
        from slowql.rules.performance.redshift import OrderByWithoutLimitRedshiftRule
        assert OrderByWithoutLimitRedshiftRule().check(_q("SELECT id FROM t ORDER BY id LIMIT 10", "redshift")) == []

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.redshift import OrderByWithoutLimitRedshiftRule
        assert OrderByWithoutLimitRedshiftRule().check(_q("SELECT id FROM t ORDER BY id", "postgresql")) == []


class TestNotInOnRedshiftRule:
    def test_fires(self) -> None:
        from slowql.rules.performance.redshift import NotInOnRedshiftRule
        assert len(NotInOnRedshiftRule().check(_q("SELECT * FROM a WHERE id NOT IN (SELECT id FROM b)", "redshift"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.performance.redshift import NotInOnRedshiftRule
        assert NotInOnRedshiftRule().check(_q("SELECT * FROM a WHERE id NOT IN (SELECT id FROM b)", "postgresql")) == []


class TestUnloadWithoutParallelRule:
    def test_fires(self) -> None:
        from slowql.rules.cost.redshift import UnloadWithoutParallelRule
        assert len(UnloadWithoutParallelRule().check(_q("UNLOAD ('SELECT * FROM t') TO 's3://bucket/prefix'", "redshift"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.cost.redshift import UnloadWithoutParallelRule
        assert UnloadWithoutParallelRule().check(_q("UNLOAD ('SELECT * FROM t') TO 's3://bucket/prefix'", "postgresql")) == []


class TestCopyWithoutManifestRule:
    def test_fires(self) -> None:
        from slowql.rules.reliability.redshift import CopyWithoutManifestRule
        assert len(CopyWithoutManifestRule().check(_q("COPY t FROM 's3://bucket/data/'", "redshift"))) > 0

    def test_skips_pg(self) -> None:
        from slowql.rules.reliability.redshift import CopyWithoutManifestRule
        assert CopyWithoutManifestRule().check(_q("COPY t FROM 's3://bucket/data/'", "postgresql")) == []


# ── Catalog ──────────────────────────────────────────────────────────


class TestPhase4Catalog:
    def test_all_in_catalog(self) -> None:
        from slowql.rules.catalog import get_all_rules
        ids = {r.id for r in get_all_rules()}
        for eid in ["SEC-SQLITE-001", "PERF-SQLITE-001", "PERF-SQLITE-002",
                     "QUAL-SQLITE-001", "REL-SQLITE-001",
                     "PERF-RS-001", "PERF-RS-002", "PERF-RS-003",
                     "COST-RS-001", "REL-RS-001"]:
            assert eid in ids, f"{eid} missing"

    def test_total(self) -> None:
        from slowql.rules.catalog import get_all_rules
        assert len(get_all_rules()) == 261
