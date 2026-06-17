use slowql_lib::models::{Location, Query};
use slowql_lib::rules::security;
use slowql_lib::rules::Rule;

fn q(sql: &str, dialect: &str, qt: &str) -> Query {
    Query {
        raw: sql.to_string(),
        normalized: sql.to_string(),
        dialect: dialect.to_string(),
        location: Location::new(1, 1),
        start_offset: None,
        end_offset: None,
        tables: vec![],
        columns: vec![],
        query_type: Some(qt.to_string()),
        is_ddl: false,
        is_dynamic: false,
        complexity_score: 0,
        source_context: "application".to_string(), ..Default::default()
    }
}

fn find<'a>(rules: &'a [Box<dyn Rule>], id: &str) -> &'a dyn Rule {
    rules.iter().find(|r| r.id() == id).map(|r| r.as_ref())
        .unwrap_or_else(|| panic!("rule {} not found", id))
}

fn all() -> Vec<Box<dyn Rule>> { security::all_rules() }

// ---------------------------------------------------------------------------
// Verify rule count
// ---------------------------------------------------------------------------
#[test]
fn security_has_61_rules() {
    assert_eq!(all().len(), 61);
}

// ---------------------------------------------------------------------------
// Injection rules (13 rules)
// ---------------------------------------------------------------------------
#[test]
fn inj_001_string_concat() {
    let r = all(); let rule = find(&r, "SEC-INJ-001");
    assert!(!rule.check(&q("SELECT * FROM users WHERE name = 'x' + user_input", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM users WHERE id = 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_001_dynamic_flag() {
    let r = all(); let rule = find(&r, "SEC-INJ-001");
    let mut query = q("SELECT * FROM users WHERE id = 1", "postgresql", "SELECT");
    query.is_dynamic = true;
    assert!(!rule.check(&query).is_empty());
}

#[test]
fn inj_002_exec() {
    let r = all(); let rule = find(&r, "SEC-INJ-002");
    assert!(!rule.check(&q("EXEC('SELECT 1')", "tsql", "SELECT")).is_empty());
    assert!(!rule.check(&q("EXECUTE IMMEDIATE sql_stmt", "oracle", "SELECT")).is_empty());
    assert!(!rule.check(&q("sp_executesql @sql", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_003_tautology() {
    let r = all(); let rule = find(&r, "SEC-INJ-003");
    assert!(!rule.check(&q("SELECT * FROM u WHERE id=1 OR 1=1", "postgresql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT * FROM u WHERE id=1 OR 'a'='a'", "postgresql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT * FROM u WHERE id=1 OR TRUE", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM u WHERE id=1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_004_sleep() {
    let r = all(); let rule = find(&r, "SEC-INJ-004");
    assert!(!rule.check(&q("SELECT SLEEP(5)", "mysql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT pg_sleep(5)", "postgresql", "SELECT")).is_empty());
    assert!(!rule.check(&q("WAITFOR DELAY '00:00:05'", "tsql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT BENCHMARK(1000,SHA1('x'))", "mysql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_005_second_order() {
    let r = all(); let rule = find(&r, "SEC-INJ-005");
    // Literal VALUES no longer triggers (precision fix)
    assert!(rule.check(&q("INSERT INTO users (username, email) VALUES ('a','b')", "postgresql", "INSERT")).is_empty());
    // But dynamic INSERT does trigger
    let mut dq = q("INSERT INTO users (username, email) VALUES ('a','b')", "postgresql", "INSERT");
    dq.is_dynamic = true;
    assert!(!rule.check(&dq).is_empty());
    // UPDATE with literal value does not fire (precision: requires dynamic/concatenation)
    assert!(rule.check(&q("UPDATE users SET description = 'x'", "postgresql", "UPDATE")).is_empty());
    // UPDATE with concatenation DOES fire
    assert!(!rule.check(&q("UPDATE users SET description = input || ' suffix'", "postgresql", "UPDATE")).is_empty());
    assert!(rule.check(&q("INSERT INTO settings (key, value) VALUES ('a','b')", "postgresql", "INSERT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM users", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_007_ldap() {
    let r = all(); let rule = find(&r, "SEC-INJ-007");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_008_nosql() {
    let r = all(); let rule = find(&r, "SEC-INJ-008");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_009_xpath() {
    let r = all(); let rule = find(&r, "SEC-INJ-009");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_010_ssti() {
    let r = all(); let rule = find(&r, "SEC-INJ-010");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn inj_011_json() {
    let r = all(); let rule = find(&r, "SEC-INJ-011");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn pg_003_raise_notice_dialect() {
    let r = all(); let rule = find(&r, "SEC-PG-003");
    assert!(!rule.check(&q("RAISE NOTICE 'hello' || user_name", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("RAISE NOTICE 'hello' || user_name", "mysql", "SELECT")).is_empty());
}

#[test]
fn ora_002_dbms_sql_dialect() {
    let r = all(); let rule = find(&r, "SEC-ORA-002");
    assert!(!rule.check(&q("DBMS_SQL.PARSE(c, stmt, 1)", "oracle", "SELECT")).is_empty());
    assert!(rule.check(&q("DBMS_SQL.PARSE(c, stmt, 1)", "postgresql", "SELECT")).is_empty());
}

#[test]
fn ora_003_execute_immediate_dialect() {
    let r = all(); let rule = find(&r, "SEC-ORA-003");
    assert!(!rule.check(&q("EXECUTE IMMEDIATE 'SELECT ' || col FROM t", "oracle", "SELECT")).is_empty());
    assert!(rule.check(&q("EXECUTE IMMEDIATE 'SELECT ' || col FROM t", "postgresql", "SELECT")).is_empty());
}

// ---------------------------------------------------------------------------
// Authentication rules (5 rules)
// ---------------------------------------------------------------------------
#[test]
fn auth_001_hardcoded_password() {
    let r = all(); let rule = find(&r, "SEC-AUTH-001");
    assert!(!rule.check(&q("password='secret123'", "postgresql", "SELECT")).is_empty());
    assert!(!rule.check(&q("token='abc123'", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT password FROM users", "postgresql", "SELECT")).is_empty());
}

#[test]
fn auth_002_grant_public() {
    let r = all(); let rule = find(&r, "SEC-AUTH-002");
    assert!(!rule.check(&q("GRANT SELECT ON users TO PUBLIC", "postgresql", "GRANT")).is_empty());
    assert!(rule.check(&q("GRANT SELECT ON users TO app_role", "postgresql", "GRANT")).is_empty());
}

#[test]
fn auth_003_user_no_password() {
    let r = all(); let rule = find(&r, "SEC-AUTH-003");
    assert!(!rule.check(&q("CREATE USER testuser", "postgresql", "CREATE")).is_empty());
    assert!(rule.check(&q("CREATE USER testuser IDENTIFIED BY 'pass'", "oracle", "CREATE")).is_empty());
    assert!(rule.check(&q("CREATE USER testuser WITH PASSWORD 'pass'", "tsql", "CREATE")).is_empty());
}

#[test]
fn auth_004_policy_bypass() {
    let r = all(); let rule = find(&r, "SEC-AUTH-004");
    assert!(!rule.check(&q("CHECK_POLICY = OFF", "tsql", "SELECT")).is_empty());
    assert!(!rule.check(&q("CHECK_EXPIRATION = OFF", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("CHECK_POLICY = ON", "tsql", "SELECT")).is_empty());
}

#[test]
fn auth_005_grant_all() {
    let r = all(); let rule = find(&r, "SEC-AUTH-005");
    assert!(!rule.check(&q("GRANT ALL ON schema TO user1", "postgresql", "GRANT")).is_empty());
    assert!(rule.check(&q("GRANT SELECT ON t TO user1", "postgresql", "GRANT")).is_empty());
}

// ---------------------------------------------------------------------------
// Authorization rules (3 rules)
// ---------------------------------------------------------------------------
#[test]
fn authz_001_priv_escalation() {
    let r = all(); let rule = find(&r, "SEC-AUTHZ-001");
    assert!(!rule.check(&q("GRANT sysadmin TO hacker", "tsql", "GRANT")).is_empty());
    assert!(!rule.check(&q("ALTER ROLE db_owner ADD MEMBER hacker", "tsql", "ALTER")).is_empty());
    assert!(rule.check(&q("GRANT SELECT ON t TO reader", "postgresql", "GRANT")).is_empty());
}

#[test]
fn authz_002_ownership_change() {
    let r = all(); let rule = find(&r, "SEC-AUTHZ-002");
    assert!(!rule.check(&q("ALTER AUTHORIZATION ON SCHEMA::dbo TO hacker", "tsql", "ALTER")).is_empty());
    assert!(rule.check(&q("ALTER TABLE t ADD COLUMN c INT", "postgresql", "ALTER")).is_empty());
}

#[test]
fn authz_003_horizontal_bypass() {
    let r = all(); let rule = find(&r, "SEC-AUTHZ-003");
    assert!(!rule.check(&q("SELECT * FROM orders", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM orders WHERE user_id = 1", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM settings", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("INSERT INTO orders VALUES (1)", "postgresql", "INSERT")).is_empty());
}

// ---------------------------------------------------------------------------
// Cryptography rules (4 rules)
// ---------------------------------------------------------------------------
#[test]
fn crypto_001_weak_hash() {
    let r = all(); let rule = find(&r, "SEC-CRYPTO-001");
    assert!(!rule.check(&q("SELECT MD5(password) FROM users", "postgresql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT SHA1(token) FROM t", "mysql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT MD5(data) FROM t", "postgresql", "SELECT")).is_empty());
}

#[test]
fn crypto_002_plaintext_pw() {
    let r = all(); let rule = find(&r, "SEC-CRYPTO-002");
    assert!(!rule.check(&q("INSERT INTO users (password) VALUES ('mysecretpass')", "postgresql", "INSERT")).is_empty());
    assert!(rule.check(&q("SELECT password FROM users", "postgresql", "SELECT")).is_empty());
}

#[test]
fn crypto_003_hardcoded_key() {
    let r = all(); let rule = find(&r, "SEC-CRYPTO-003");
    assert!(!rule.check(&q("SELECT AES_ENCRYPT(data, 'MySecretKey12345')", "mysql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT AES_ENCRYPT(data, @key)", "mysql", "SELECT")).is_empty());
}

#[test]
fn crypto_004_weak_algo() {
    let r = all(); let rule = find(&r, "SEC-CRYPTO-004");
    assert!(!rule.check(&q("SELECT DES_ENCRYPT(data)", "mysql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT RC4(data)", "mysql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT AES_ENCRYPT(data, key)", "mysql", "SELECT")).is_empty());
}

// ---------------------------------------------------------------------------
// Data protection rules (6 rules)
// ---------------------------------------------------------------------------
#[test]
fn data_001_exfiltration() {
    let r = all(); let rule = find(&r, "SEC-DATA-001");
    assert!(!rule.check(&q("SELECT * INTO OUTFILE '/tmp/data.csv' FROM users", "mysql", "SELECT")).is_empty());
    assert!(!rule.check(&q("BULK INSERT t FROM '/data.csv'", "tsql", "INSERT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM users", "postgresql", "SELECT")).is_empty());
}

#[test]
fn data_002_remote() {
    let r = all(); let rule = find(&r, "SEC-DATA-002");
    assert!(!rule.check(&q("SELECT * FROM OPENROWSET('SQLNCLI', ...)", "tsql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT dblink('host=h dbname=d', 'SELECT 1')", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn mysql_001_load_data_dialect() {
    let r = all(); let rule = find(&r, "SEC-MYSQL-001");
    assert!(!rule.check(&q("LOAD DATA LOCAL INFILE '/tmp/f' INTO TABLE t", "mysql", "INSERT")).is_empty());
    assert!(rule.check(&q("LOAD DATA LOCAL INFILE '/tmp/f' INTO TABLE t", "postgresql", "INSERT")).is_empty());
}

#[test]
fn rs_001_copy_creds_dialect() {
    let r = all(); let rule = find(&r, "SEC-RS-001");
    assert!(!rule.check(&q("COPY t FROM 's3://b/f' CREDENTIALS 'aws_access_key_id=X'", "redshift", "COPY")).is_empty());
    assert!(rule.check(&q("COPY t FROM 's3://b/f' CREDENTIALS 'aws_access_key_id=X'", "postgresql", "COPY")).is_empty());
}

#[test]
fn sf_001_copy_creds_dialect() {
    let r = all(); let rule = find(&r, "SEC-SF-001");
    assert!(!rule.check(&q("COPY INTO t FROM @s AWS_KEY_ID='x' AWS_SECRET_KEY='y'", "snowflake", "COPY")).is_empty());
    assert!(rule.check(&q("COPY INTO t FROM @s AWS_KEY_ID='x'", "postgresql", "COPY")).is_empty());
}

#[test]
fn sf_002_clone_grants() {
    let r = all(); let rule = find(&r, "SEC-SF-002");
    assert!(!rule.check(&q("CREATE TABLE t2 CLONE t1", "snowflake", "CREATE")).is_empty());
    assert!(rule.check(&q("CREATE TABLE t2 CLONE t1 COPY GRANTS", "snowflake", "CREATE")).is_empty());
    assert!(rule.check(&q("CREATE TABLE t2 CLONE t1", "postgresql", "CREATE")).is_empty());
}

// ---------------------------------------------------------------------------
// Command rules (10 rules)
// ---------------------------------------------------------------------------
#[test]
fn cmd_001_tsql_xp_cmdshell() {
    let r = all(); let rule = find(&r, "SEC-CMD-001");
    assert!(!rule.check(&q("EXEC xp_cmdshell 'dir'", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("EXEC xp_cmdshell 'dir'", "postgresql", "SELECT")).is_empty());
}

#[test]
fn cmd_001_pg_read_file() {
    let r = all(); let rule = find(&r, "SEC-CMD-001-PG");
    assert!(!rule.check(&q("SELECT pg_read_file('/etc/passwd')", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT pg_read_file('/etc/passwd')", "mysql", "SELECT")).is_empty());
}

#[test]
fn path_001_traversal() {
    let r = all(); let rule = find(&r, "SEC-PATH-001");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn path_002_local_file() {
    let r = all(); let rule = find(&r, "SEC-PATH-002");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn ssrf_001() {
    let r = all(); let rule = find(&r, "SEC-SSRF-001");
    assert!(!rule.check(&q("SELECT UTL_HTTP.REQUEST('http://internal')", "oracle", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn ora_001_utl() {
    let r = all(); let rule = find(&r, "SEC-ORA-001");
    assert!(!rule.check(&q("UTL_HTTP.REQUEST('http://x')", "oracle", "SELECT")).is_empty());
    assert!(!rule.check(&q("UTL_FILE.FOPEN('/tmp','f','r')", "oracle", "SELECT")).is_empty());
    assert!(rule.check(&q("UTL_FILE.FOPEN('/tmp','f','r')", "postgresql", "SELECT")).is_empty());
}

#[test]
fn tsql_001_openrowset() {
    let r = all(); let rule = find(&r, "SEC-TSQL-001");
    assert!(!rule.check(&q("SELECT * FROM OPENROWSET('x','y','z')", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM OPENROWSET('x','y','z')", "postgresql", "SELECT")).is_empty());
}

#[test]
fn tsql_002_sp_oacreate() {
    let r = all(); let rule = find(&r, "SEC-TSQL-002");
    assert!(!rule.check(&q("EXEC sp_OACreate 'MSXML.DOMDocument'", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("EXEC sp_OACreate 'MSXML.DOMDocument'", "postgresql", "SELECT")).is_empty());
}

#[test]
fn ch_001_url_function() {
    let r = all(); let rule = find(&r, "SEC-CH-001");
    assert!(!rule.check(&q("SELECT * FROM url('http://internal/api')", "clickhouse", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM url('http://internal/api')", "postgresql", "SELECT")).is_empty());
}

#[test]
fn sqlite_001_attach() {
    let r = all(); let rule = find(&r, "SEC-SQLITE-001");
    assert!(!rule.check(&q("ATTACH DATABASE '/etc/passwd' AS db2", "sqlite", "SELECT")).is_empty());
    assert!(rule.check(&q("ATTACH DATABASE '/etc/passwd' AS db2", "postgresql", "SELECT")).is_empty());
}

// ---------------------------------------------------------------------------
// Configuration rules (8 rules)
// ---------------------------------------------------------------------------
#[test]
fn cfg_001_dangerous_config() {
    let r = all(); let rule = find(&r, "SEC-CFG-001");
    assert!(!rule.check(&q("sp_configure 'xp_cmdshell', 1", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("sp_configure 'xp_cmdshell', 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn priv_001_overprivileged() {
    let r = all(); let rule = find(&r, "SEC-PRIV-001");
    assert!(!rule.check(&q("EXECUTE AS USER='dbo'", "tsql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SECURITY DEFINER", "postgresql", "SELECT")).is_empty());
    assert!(!rule.check(&q("WITH GRANT OPTION", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn config_001_hardcoded_creds() {
    let r = all(); let rule = find(&r, "SEC-CONFIG-001");
    assert!(!rule.check(&q("PASSWORD='SuperSecret!'", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn config_002_weak_ssl() {
    let r = all(); let rule = find(&r, "SEC-CONFIG-002");
    assert!(!rule.check(&q("sslmode=disable", "postgresql", "SELECT")).is_empty());
    assert!(!rule.check(&q("Encrypt=false", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("sslmode=verify-full", "postgresql", "SELECT")).is_empty());
}

#[test]
fn config_003_default_creds() {
    let r = all(); let rule = find(&r, "SEC-CONFIG-003");
    assert!(!rule.check(&q("sa Password='password'", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn config_004_permissive() {
    let r = all(); let rule = find(&r, "SEC-CONFIG-004");
    assert!(!rule.check(&q("CREATE USER test@'%'", "mysql", "CREATE")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn pg_002_search_path() {
    let r = all(); let rule = find(&r, "SEC-PG-002");
    assert!(!rule.check(&q("SET search_path TO public, evil_schema", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SET search_path TO public", "mysql", "SELECT")).is_empty());
}

#[test]
fn pg_004_definer_no_search_path() {
    let r = all(); let rule = find(&r, "SEC-PG-004");
    assert!(!rule.check(&q("CREATE FUNCTION f() RETURNS void SECURITY DEFINER AS $$ BEGIN END $$", "postgresql", "CREATE")).is_empty());
    assert!(rule.check(&q("CREATE FUNCTION f() RETURNS void SECURITY DEFINER SET search_path = pg_catalog AS $$ BEGIN END $$", "postgresql", "CREATE")).is_empty());
    assert!(rule.check(&q("SECURITY DEFINER SET search_path = pg_catalog", "mysql", "CREATE")).is_empty());
}

// ---------------------------------------------------------------------------
// DoS rules (4 rules)
// ---------------------------------------------------------------------------
#[test]
fn dos_001_recursive_cte() {
    let r = all(); let rule = find(&r, "SEC-DOS-001");
    assert!(!rule.check(&q("WITH RECURSIVE cte AS (SELECT 1 UNION ALL SELECT n+1 FROM cte) SELECT * FROM cte", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("WITH RECURSIVE cte AS (SELECT 1 UNION ALL SELECT n+1 FROM cte) SELECT * FROM cte OPTION (MAXRECURSION 100)", "tsql", "SELECT")).is_empty());
}

#[test]
fn dos_002_redos() {
    let r = all(); let rule = find(&r, "SEC-DOS-002");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn pg_001_pg_sleep_dialect() {
    let r = all(); let rule = find(&r, "SEC-PG-001");
    assert!(!rule.check(&q("SELECT pg_sleep(5)", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT pg_sleep(5)", "mysql", "SELECT")).is_empty());
}

#[test]
fn tsql_004_waitfor() {
    let r = all(); let rule = find(&r, "PERF-TSQL-004");
    assert!(!rule.check(&q("WAITFOR DELAY '00:00:05'", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("WAITFOR DELAY '00:00:05'", "postgresql", "SELECT")).is_empty());
}

// ---------------------------------------------------------------------------
// Information rules (4 rules)
// ---------------------------------------------------------------------------
#[test]
fn info_001_version() {
    let r = all(); let rule = find(&r, "SEC-INFO-001");
    assert!(!rule.check(&q("SELECT @@VERSION", "tsql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT VERSION()", "mysql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn info_002_schema_disclosure() {
    let r = all(); let rule = find(&r, "SEC-INFO-002");
    assert!(!rule.check(&q("SELECT * FROM INFORMATION_SCHEMA.TABLES", "tsql", "SELECT")).is_empty());
    assert!(!rule.check(&q("SELECT * FROM sys.tables", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn info_003_timing() {
    let r = all(); let rule = find(&r, "SEC-INFO-003");
    assert!(!rule.check(&q("SLEEP(5)", "mysql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn info_004_verbose_error() {
    let r = all(); let rule = find(&r, "SEC-INFO-004");
    assert!(!rule.check(&q("RAISERROR('Error: ' + ERROR_MESSAGE(), 16, 1)", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

// ---------------------------------------------------------------------------
// Logging rules (2 rules)
// ---------------------------------------------------------------------------
#[test]
fn log_001_sensitive_error() {
    let r = all(); let rule = find(&r, "SEC-LOG-001");
    assert!(!rule.check(&q("PRINT 'Error for password: ' + @password", "tsql", "SELECT")).is_empty());
    assert!(rule.check(&q("PRINT 'Error occurred'", "tsql", "SELECT")).is_empty());
}

#[test]
fn log_002_audit_manipulation() {
    let r = all(); let rule = find(&r, "SEC-LOG-002");
    assert!(!rule.check(&q("DELETE FROM audit_log WHERE id = 1", "postgresql", "DELETE")).is_empty());
    assert!(!rule.check(&q("TRUNCATE audit_trail", "postgresql", "TRUNCATE")).is_empty());
    assert!(rule.check(&q("SELECT * FROM audit_log", "postgresql", "SELECT")).is_empty());
}

// ---------------------------------------------------------------------------
// Session rules (2 rules)
// ---------------------------------------------------------------------------
#[test]
fn session_001_insecure_storage() {
    let r = all(); let rule = find(&r, "SEC-SESSION-001");
    assert!(rule.check(&q("SELECT 1", "postgresql", "SELECT")).is_empty());
}

#[test]
fn session_002_no_timeout() {
    let r = all(); let rule = find(&r, "SEC-SESSION-002");
    assert!(!rule.check(&q("SELECT * FROM sessions WHERE session_token = 'abc'", "postgresql", "SELECT")).is_empty());
    assert!(rule.check(&q("SELECT * FROM sessions WHERE session_token = 'abc' AND expires_at > NOW()", "postgresql", "SELECT")).is_empty());
}
