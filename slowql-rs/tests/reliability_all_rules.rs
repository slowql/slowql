use slowql_lib::models::{Location, Query};
use slowql_lib::rules::reliability;
use slowql_lib::rules::Rule;

fn q(sql: &str, dialect: &str, qt: &str) -> Query {
    Query { raw: sql.to_string(), normalized: sql.to_string(), dialect: dialect.to_string(), location: Location::new(1, 1), start_offset: None, end_offset: None, tables: vec![], columns: vec![], query_type: Some(qt.to_string()), is_ddl: false, is_dynamic: false, complexity_score: 0, source_context: "application".to_string(), ..Default::default() }
}
fn find<'a>(rules: &'a [Box<dyn Rule>], id: &str) -> &'a dyn Rule { rules.iter().find(|r| r.id() == id).map(|r| r.as_ref()).unwrap_or_else(|| panic!("rule {} not found", id)) }
fn all() -> Vec<Box<dyn Rule>> { reliability::all_rules() }

#[test] fn reliability_rule_count() { assert_eq!(all().len(), 40); }

#[test] fn rel_data_001() { let r=all(); let rule=find(&r,"REL-DATA-001"); assert!(!rule.check(&q("DELETE FROM users","postgresql","DELETE")).is_empty()); assert!(rule.check(&q("DELETE FROM users WHERE id=1","postgresql","DELETE")).is_empty()); }
#[test] fn rel_data_002() { let r=all(); let rule=find(&r,"REL-DATA-002"); assert!(!rule.check(&q("TRUNCATE TABLE users","postgresql","TRUNCATE")).is_empty()); }
#[test] fn rel_data_003() { let r=all(); let rule=find(&r,"REL-DATA-003"); assert!(!rule.check(&q("ALTER TABLE t DROP COLUMN c","postgresql","ALTER")).is_empty()); assert!(rule.check(&q("ALTER TABLE t ADD COLUMN c INT","postgresql","ALTER")).is_empty()); }
#[test] fn rel_data_004() { let r=all(); let rule=find(&r,"REL-DATA-004"); assert!(!rule.check(&q("DROP TABLE users","postgresql","DROP")).is_empty()); assert!(rule.check(&q("SELECT 1","postgresql","SELECT")).is_empty()); }
#[test] fn rel_txn_001() { let r=all(); let rule=find(&r,"REL-TXN-001"); assert!(!rule.check(&q("BEGIN; UPDATE t SET x=1; COMMIT","postgresql","SELECT")).is_empty()); }
#[test] fn rel_txn_002() { let r=all(); let rule=find(&r,"REL-TXN-002"); assert!(!rule.check(&q("SET autocommit = 0","mysql","SELECT")).is_empty()); }
#[test] fn rel_txn_003() { let r=all(); let rule=find(&r,"REL-TXN-003"); assert!(!rule.check(&q("BEGIN; COMMIT","postgresql","SELECT")).is_empty()); }
#[test] fn rel_err_001() { let r=all(); let rule=find(&r,"REL-ERR-001"); assert!(!rule.check(&q("WHEN OTHERS THEN NULL","oracle","SELECT")).is_empty()); }
#[test] fn rel_idem_001() { let r=all(); let rule=find(&r,"REL-IDEM-001"); assert!(!rule.check(&q("INSERT INTO t VALUES (1)","postgresql","INSERT")).is_empty()); assert!(rule.check(&q("INSERT INTO t VALUES (1) ON CONFLICT DO NOTHING","postgresql","INSERT")).is_empty()); }
#[test] fn rel_race_002() { let r=all(); let rule=find(&r,"REL-RACE-002"); assert!(!rule.check(&q("IF NOT EXISTS (SELECT 1 FROM t WHERE id=1) INSERT INTO t VALUES (1)","tsql","SELECT")).is_empty()); }
#[test] fn rel_fk_002() {
    let r=all(); let rule=find(&r,"REL-FK-002");
    // Mass delete on parent table fires
    assert!(!rule.check(&q("DELETE FROM users","postgresql","DELETE")).is_empty());
    // Targeted single-row delete does NOT fire (precision fix)
    assert!(rule.check(&q("DELETE FROM users WHERE id=1","postgresql","DELETE")).is_empty());
}
#[test] fn rel_mysql_001() { let r=all(); let rule=find(&r,"REL-MYSQL-001"); assert!(!rule.check(&q("INSERT IGNORE INTO t VALUES (1)","mysql","INSERT")).is_empty()); assert!(rule.check(&q("INSERT IGNORE INTO t VALUES (1)","postgresql","INSERT")).is_empty()); }
#[test] fn rel_mysql_002() { let r=all(); let rule=find(&r,"REL-MYSQL-002"); assert!(!rule.check(&q("REPLACE INTO t VALUES (1)","mysql","INSERT")).is_empty()); assert!(rule.check(&q("REPLACE INTO t VALUES (1)","postgresql","INSERT")).is_empty()); }
#[test] fn rel_mysql_005() { let r=all(); let rule=find(&r,"REL-MYSQL-005"); assert!(!rule.check(&q("CREATE TABLE t (id INT) ENGINE=MyISAM","mysql","CREATE")).is_empty()); assert!(rule.check(&q("CREATE TABLE t (id INT) ENGINE=MyISAM","postgresql","CREATE")).is_empty()); }
#[test] fn rel_tsql_001() { let r=all(); let rule=find(&r,"REL-TSQL-001"); assert!(!rule.check(&q("SELECT @@IDENTITY","tsql","SELECT")).is_empty()); assert!(rule.check(&q("SELECT @@IDENTITY","postgresql","SELECT")).is_empty()); }
#[test] fn rel_tsql_002() { let r=all(); let rule=find(&r,"REL-TSQL-002"); assert!(!rule.check(&q("MERGE INTO target USING source ON target.id=source.id","tsql","MERGE")).is_empty()); assert!(rule.check(&q("MERGE INTO target WITH (HOLDLOCK) USING source ON target.id=source.id","tsql","MERGE")).is_empty()); }
#[test] fn rel_pg_002() { let r=all(); let rule=find(&r,"REL-PG-002"); assert!(!rule.check(&q("CREATE INDEX idx ON t (col)","postgresql","CREATE")).is_empty()); assert!(rule.check(&q("CREATE INDEX CONCURRENTLY idx ON t (col)","postgresql","CREATE")).is_empty()); assert!(rule.check(&q("CREATE INDEX idx ON t (col)","mysql","CREATE")).is_empty()); }
#[test] fn rel_ora_001() { let r=all(); let rule=find(&r,"REL-ORA-001"); assert!(!rule.check(&q("SELECT * FROM t CONNECT BY PRIOR parent_id = id","oracle","SELECT")).is_empty()); assert!(rule.check(&q("SELECT * FROM t CONNECT BY NOCYCLE PRIOR parent_id = id","oracle","SELECT")).is_empty()); }
#[test] fn rel_ora_003() { let r=all(); let rule=find(&r,"REL-ORA-003"); assert!(!rule.check(&q("PRAGMA AUTONOMOUS_TRANSACTION","oracle","SELECT")).is_empty()); assert!(rule.check(&q("PRAGMA AUTONOMOUS_TRANSACTION","postgresql","SELECT")).is_empty()); }
#[test] fn rel_bq_001() { let r=all(); let rule=find(&r,"REL-BQ-001"); assert!(!rule.check(&q("DELETE FROM t","bigquery","DELETE")).is_empty()); assert!(rule.check(&q("DELETE FROM t WHERE dt='2024-01-01'","bigquery","DELETE")).is_empty()); assert!(rule.check(&q("DELETE FROM t","postgresql","DELETE")).is_empty()); }
#[test] fn rel_presto_001() { let r=all(); let rule=find(&r,"REL-PRESTO-001"); assert!(!rule.check(&q("INSERT OVERWRITE t SELECT * FROM s","presto","INSERT")).is_empty()); assert!(rule.check(&q("INSERT OVERWRITE t PARTITION (dt='2024') SELECT * FROM s","presto","INSERT")).is_empty()); }
#[test] fn rel_spark_001() { let r=all(); let rule=find(&r,"REL-SPARK-001"); assert!(!rule.check(&q("INSERT OVERWRITE t SELECT * FROM s","spark","INSERT")).is_empty()); assert!(rule.check(&q("INSERT OVERWRITE t SELECT * FROM s","postgresql","INSERT")).is_empty()); }
#[test] fn rel_sqlite_001() { let r=all(); let rule=find(&r,"REL-SQLITE-001"); assert!(!rule.check(&q("ALTER TABLE t DROP COLUMN c","sqlite","ALTER")).is_empty()); assert!(rule.check(&q("ALTER TABLE t DROP COLUMN c","postgresql","ALTER")).is_empty()); }
#[test] fn rel_sqlite_002() { let r=all(); let rule=find(&r,"REL-SQLITE-002"); assert!(!rule.check(&q("PRAGMA foreign_keys = OFF","sqlite","SELECT")).is_empty()); assert!(rule.check(&q("PRAGMA foreign_keys = OFF","postgresql","SELECT")).is_empty()); }
