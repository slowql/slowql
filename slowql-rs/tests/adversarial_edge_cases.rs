//! Adversarial edge case corpus for enterprise SQL patterns.
//! Every test documents: the SQL, the context, what should fire, what should NOT fire.
//! Zero tolerance for false positives. Zero tolerance for false negatives on proven rules.

use slowql_lib::engine::Engine;
use slowql_lib::config::Config;
use slowql_lib::models::issue::RuleConfidence;

fn analyze(sql: &str, dialect: Option<&str>, file_path: Option<&str>) -> Vec<(String, String)> {
    let engine = Engine::with_default_config();
    let result = engine.analyze(sql, dialect, file_path);
    result.issues.iter().map(|i| (i.rule_id.clone(), i.confidence.as_str().to_string())).collect()
}

fn analyze_with_config(sql: &str, dialect: Option<&str>, file_path: Option<&str>, config: Config) -> Vec<(String, String)> {
    let engine = Engine::new(config);
    let result = engine.analyze(sql, dialect, file_path);
    result.issues.iter().map(|i| (i.rule_id.clone(), i.confidence.as_str().to_string())).collect()
}

fn has_rule(issues: &[(String, String)], rule: &str) -> bool {
    issues.iter().any(|(id, _)| id == rule)
}

fn has_no_rule(issues: &[(String, String)], rule: &str) -> bool {
    !has_rule(issues, rule)
}

// ============================================================================
// CATEGORY 1: Context awareness - same SQL, different contexts
// ============================================================================

#[test]
fn ctx_select_star_adhoc_no_perf() {
    let issues = analyze("SELECT * FROM users", Some("postgresql"), None);
    assert!(has_no_rule(&issues, "PERF-SCAN-001"), "SELECT * in adhoc should not fire PERF-SCAN-001");
    assert!(has_no_rule(&issues, "PERF-SCAN-003"), "SELECT * in adhoc should not fire PERF-SCAN-003");
    assert!(has_no_rule(&issues, "COST-COMPUTE-001"), "SELECT * in adhoc should not fire COST-COMPUTE-001");
}

#[test]
fn ctx_select_star_application_fires() {
    let issues = analyze("SELECT * FROM users", Some("postgresql"), Some("src/app.sql"));
    assert!(has_rule(&issues, "PERF-SCAN-001"), "SELECT * in application should fire PERF-SCAN-001");
}

#[test]
fn ctx_select_star_migration_no_perf() {
    let issues = analyze("SELECT * FROM users", Some("postgresql"), Some("migrations/001.sql"));
    assert!(has_no_rule(&issues, "PERF-SCAN-001"), "SELECT * in migration should not fire PERF-SCAN-001");
    assert!(has_no_rule(&issues, "COST-COMPUTE-001"), "SELECT * in migration should not fire COST-COMPUTE-001");
}

#[test]
fn ctx_select_star_test_no_perf() {
    let issues = analyze("SELECT * FROM users", Some("postgresql"), Some("tests/test.sql"));
    assert!(has_no_rule(&issues, "PERF-SCAN-001"), "SELECT * in test should not fire PERF-SCAN-001");
}

#[test]
fn ctx_select_star_seed_no_perf() {
    let issues = analyze("SELECT * FROM users", Some("postgresql"), Some("seeds/data.sql"));
    assert!(has_no_rule(&issues, "PERF-SCAN-001"), "SELECT * in seed should not fire PERF-SCAN-001");
}

#[test]
fn ctx_delete_no_where_fires_everywhere() {
    // DELETE without WHERE is dangerous in every context
    for path in &[None, Some("src/app.sql"), Some("migrations/001.sql"), Some("tests/t.sql")] {
        let issues = analyze("DELETE FROM users", Some("postgresql"), *path);
        assert!(has_rule(&issues, "REL-DATA-001"),
            "DELETE without WHERE should fire REL-DATA-001 in context {:?}", path);
    }
}

#[test]
fn ctx_insert_idempotency_only_in_application() {
    // Application context: should fire
    let issues = analyze(
        "INSERT INTO users (id, email) VALUES (1, 'a@b.com')",
        Some("postgresql"), Some("src/queries.sql")
    );
    assert!(has_rule(&issues, "REL-IDEM-001"), "plain INSERT in application should fire REL-IDEM-001");

    // Migration context: should NOT fire
    let issues = analyze(
        "INSERT INTO users (id, email) VALUES (1, 'a@b.com')",
        Some("postgresql"), Some("migrations/001.sql")
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"), "plain INSERT in migration should not fire REL-IDEM-001");

    // Test context: should NOT fire
    let issues = analyze(
        "INSERT INTO users (id, email) VALUES (1, 'a@b.com')",
        Some("postgresql"), Some("tests/test.sql")
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"), "plain INSERT in test should not fire REL-IDEM-001");

    // Seed context: should NOT fire
    let issues = analyze(
        "INSERT INTO users (id, email) VALUES (1, 'a@b.com')",
        Some("postgresql"), Some("seeds/data.sql")
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"), "plain INSERT in seed should not fire REL-IDEM-001");

    // Adhoc context: should NOT fire
    let issues = analyze(
        "INSERT INTO users (id, email) VALUES (1, 'a@b.com')",
        Some("postgresql"), None
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"), "plain INSERT in adhoc should not fire REL-IDEM-001");
}

// ============================================================================
// CATEGORY 2: Safe patterns that must NOT fire
// ============================================================================

#[test]
fn safe_select_with_where_and_limit() {
    let issues = analyze(
        "SELECT id, name FROM users WHERE status = 'active' ORDER BY id LIMIT 20",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-SCAN-001"));
    assert!(has_no_rule(&issues, "PERF-SCAN-003"));
    assert!(has_no_rule(&issues, "COST-COMPUTE-001"));
}

#[test]
fn safe_select_by_pk() {
    let issues = analyze(
        "SELECT id, name, email FROM users WHERE id = 42",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-SCAN-003"), "PK lookup should not fire unbounded select");
    assert!(has_no_rule(&issues, "COST-COMPUTE-001"), "PK lookup should not fire full table scan");
}

#[test]
fn safe_insert_on_conflict() {
    let issues = analyze(
        "INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON CONFLICT (id) DO NOTHING",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"), "ON CONFLICT is idempotent");
}

#[test]
fn safe_insert_on_duplicate_key() {
    let issues = analyze(
        "INSERT INTO users (id, email) VALUES (1, 'a@b.com') ON DUPLICATE KEY UPDATE email = VALUES(email)",
        Some("mysql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"), "ON DUPLICATE KEY is idempotent");
}

#[test]
fn safe_delete_with_pk() {
    let issues = analyze(
        "DELETE FROM users WHERE id = 42",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-DATA-001"), "DELETE with WHERE should not fire");
    assert!(has_no_rule(&issues, "PERF-SCAN-002"), "DELETE with WHERE should not fire unbounded");
}

#[test]
fn safe_update_with_where() {
    let issues = analyze(
        "UPDATE users SET status = 'inactive' WHERE id = 42",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-DATA-001"));
    assert!(has_no_rule(&issues, "PERF-SCAN-002"));
}

#[test]
fn safe_aggregation_with_group_by() {
    let issues = analyze(
        "SELECT department_id, COUNT(*) AS total FROM employees GROUP BY department_id",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-AGG-001"), "GROUP BY aggregation should not fire");
    assert!(has_no_rule(&issues, "PERF-SCAN-003"), "aggregation should not fire unbounded");
}

#[test]
fn safe_count_with_where() {
    let issues = analyze(
        "SELECT COUNT(*) FROM orders WHERE status = 'pending'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-AGG-001"), "filtered COUNT should not fire");
}

#[test]
fn safe_cte_with_where() {
    let issues = analyze(
        "WITH active AS (SELECT id FROM users WHERE status = 'active') SELECT id FROM active WHERE id = 10",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-SCAN-003"));
}

#[test]
fn safe_window_function_with_partition() {
    let issues = analyze(
        "SELECT id, ROW_NUMBER() OVER (PARTITION BY dept_id ORDER BY salary DESC) FROM employees WHERE active = true",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "COST-COMPUTE-002"), "PARTITION BY window should not fire");
}

#[test]
fn safe_window_function_global_bounded() {
    let issues = analyze(
        "SELECT id, salary, AVG(salary) OVER () AS company_avg FROM employees WHERE department_id = 1",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "COST-COMPUTE-002"), "bounded global window should not fire");
}

#[test]
fn safe_like_trailing_wildcard() {
    let issues = analyze(
        "SELECT id FROM users WHERE email LIKE 'john%'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-IDX-002"), "trailing wildcard should not fire");
}

#[test]
fn safe_parameterized_query() {
    let issues = analyze(
        "SELECT id, name FROM users WHERE id = $1",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-INJ-001"), "parameterized query should not fire injection");
}

#[test]
fn safe_grant_select() {
    let issues = analyze(
        "GRANT SELECT ON users TO readonly_role",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-AUTH-005"), "GRANT SELECT should not fire GRANT ALL");
}

#[test]
fn safe_pagination_small_offset() {
    let issues = analyze(
        "SELECT id, name FROM users ORDER BY id LIMIT 10 OFFSET 20",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "COST-PAGE-001"), "small OFFSET should not fire");
    assert!(has_no_rule(&issues, "COST-PAGE-002"), "small OFFSET should not fire deep pagination");
}

#[test]
fn safe_or_same_column() {
    let issues = analyze(
        "SELECT id FROM users WHERE status = 'active' OR status = 'pending'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-IDX-004"), "same-column OR should not fire");
}

#[test]
fn safe_information_schema_no_dynamic() {
    let issues = analyze(
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-INFO-002"), "legitimate schema inspection should not fire");
}

#[test]
fn safe_join_with_pk_where() {
    let issues = analyze(
        "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.id = 5",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-TIMEOUT-001"), "PK-bounded join should not fire timeout");
}

// ============================================================================
// CATEGORY 3: Bad patterns that MUST fire
// ============================================================================

#[test]
fn bad_delete_no_where() {
    let issues = analyze("DELETE FROM users", Some("postgresql"), Some("src/app.sql"));
    assert!(has_rule(&issues, "REL-DATA-001"), "DELETE without WHERE must fire");
    assert!(has_rule(&issues, "PERF-SCAN-002"), "unbounded DELETE must fire");
}

#[test]
fn bad_update_no_where() {
    let issues = analyze(
        "UPDATE users SET status = 'inactive'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "REL-DATA-001"), "UPDATE without WHERE must fire");
}

#[test]
fn bad_drop_table() {
    let issues = analyze("DROP TABLE users", Some("postgresql"), Some("src/app.sql"));
    assert!(has_rule(&issues, "REL-DATA-004"), "DROP TABLE must fire");
}

#[test]
fn bad_truncate() {
    let issues = analyze("TRUNCATE TABLE users", Some("postgresql"), Some("src/app.sql"));
    assert!(has_rule(&issues, "REL-DATA-002"), "TRUNCATE must fire");
}

#[test]
fn bad_sql_injection_concat() {
    let issues = analyze(
        "SELECT * FROM users WHERE name = 'x' + user_input",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "SEC-INJ-001"), "string concatenation must fire injection");
}

#[test]
fn bad_dynamic_exec() {
    let issues = analyze(
        "EXEC('SELECT * FROM users')",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "SEC-INJ-002"), "EXEC must fire dynamic SQL");
}

#[test]
fn bad_tautology() {
    let issues = analyze(
        "SELECT * FROM users WHERE id = 1 OR 1 = 1",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "SEC-INJ-003"), "tautology must fire");
    assert!(has_no_rule(&issues, "PERF-IDX-007"), "tautology 1=1 should not fire cross-column OR");
}

#[test]
fn bad_grant_all() {
    let issues = analyze(
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO PUBLIC",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "SEC-AUTH-005"), "GRANT ALL must fire");
}

#[test]
fn bad_leading_wildcard() {
    let issues = analyze(
        "SELECT id FROM users WHERE email LIKE '%@example.com'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "PERF-IDX-002"), "leading wildcard must fire");
}

#[test]
fn bad_not_in_subquery() {
    let issues = analyze(
        "SELECT id FROM users WHERE id NOT IN (SELECT user_id FROM banned)",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "PERF-SCAN-004"), "NOT IN subquery must fire");
}

#[test]
fn bad_cross_join() {
    let issues = analyze(
        "SELECT a.id, b.id FROM users a CROSS JOIN orders b",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "PERF-JOIN-001"), "CROSS JOIN must fire");
}

#[test]
fn bad_deep_offset() {
    let issues = analyze(
        "SELECT id FROM users ORDER BY id LIMIT 10 OFFSET 50000",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "PERF-IDX-005"), "deep OFFSET must fire");
}

#[test]
fn bad_time_based_injection() {
    let issues = analyze(
        "SELECT * FROM users WHERE id = 1 AND pg_sleep(5) IS NOT NULL",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "SEC-INJ-004"), "pg_sleep must fire blind injection");
}

#[test]
fn bad_function_in_where() {
    let issues = analyze(
        "SELECT id FROM users WHERE LOWER(email) = 'test@test.com'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "PERF-IDX-001"), "function in WHERE must fire");
}

// ============================================================================
// CATEGORY 4: ORM / framework generated patterns (must not fire FPs)
// ============================================================================

#[test]
fn orm_sqlalchemy_introspection() {
    let issues = analyze(
        "SELECT c.relname FROM pg_catalog.pg_class c WHERE c.relkind = 'r'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-INFO-002"), "pg_catalog query should not fire disclosure");
}

#[test]
fn orm_prisma_migration_check() {
    let issues = analyze(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '_prisma_migrations'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-INFO-002"), "ORM migration check should not fire");
}

#[test]
fn orm_django_content_type() {
    let issues = analyze(
        "SELECT id, app_label, model FROM django_content_type WHERE app_label = 'auth'",
        Some("postgresql"), Some("src/app.sql")
    );
    // This should not fire any false positives
    assert!(has_no_rule(&issues, "PERF-SCAN-003"), "filtered query should not fire unbounded");
}

// ============================================================================
// CATEGORY 5: Admin / observability patterns (must not fire FPs in adhoc)
// ============================================================================

#[test]
fn admin_explain() {
    let issues = analyze("EXPLAIN ANALYZE SELECT * FROM users WHERE id = 1", Some("postgresql"), None);
    // EXPLAIN is an admin command, adhoc context
    assert!(has_no_rule(&issues, "PERF-SCAN-001"), "EXPLAIN in adhoc should not fire");
}

#[test]
fn admin_vacuum() {
    let issues = analyze("VACUUM ANALYZE users", Some("postgresql"), None);
    assert!(issues.is_empty() || issues.iter().all(|(_, c)| c != "proven"),
        "VACUUM should not fire proven rules");
}

#[test]
fn admin_set_statement() {
    let issues = analyze("SET statement_timeout = '30s'", Some("postgresql"), None);
    assert!(issues.is_empty(), "SET in adhoc should not fire");
}

// ============================================================================
// CATEGORY 6: Confidence filtering
// ============================================================================

#[test]
fn confidence_proven_mode_filters_advisory() {
    let mut config = Config::default();
    config.analysis.min_confidence = "proven".to_string();
    let issues = analyze_with_config(
        "SELECT DISTINCT name FROM users",
        Some("postgresql"), Some("src/app.sql"), config
    );
    // PERF-SCAN-005 (DISTINCT) is advisory, should be filtered
    assert!(has_no_rule(&issues, "PERF-SCAN-005"), "advisory rule should not appear in proven mode");
}

#[test]
fn confidence_advisory_mode_shows_all() {
    let mut config = Config::default();
    config.analysis.min_confidence = "advisory".to_string();
    let issues = analyze_with_config(
        "SELECT DISTINCT name FROM users",
        Some("postgresql"), Some("src/app.sql"), config
    );
    assert!(has_rule(&issues, "PERF-SCAN-005"), "advisory rule should appear in advisory mode");
}

#[test]
fn confidence_default_filters_advisory() {
    let issues = analyze(
        "SELECT DISTINCT name FROM users",
        Some("postgresql"), Some("src/app.sql")
    );
    // Default is contextual, which should filter advisory
    assert!(has_no_rule(&issues, "PERF-SCAN-005"), "advisory should be filtered by default");
}

// ============================================================================
// CATEGORY 7: Multi-statement and edge cases
// ============================================================================

#[test]
fn multi_statement_independent() {
    let issues = analyze(
        "SELECT id FROM users WHERE id = 1; DELETE FROM orders",
        Some("postgresql"), Some("src/app.sql")
    );
    // The DELETE should fire, the SELECT should not
    assert!(has_rule(&issues, "REL-DATA-001"), "DELETE in multi-statement should fire");
}

#[test]
fn empty_query() {
    let issues = analyze("", Some("postgresql"), Some("src/app.sql"));
    assert!(issues.is_empty(), "empty query should produce no issues");
}

#[test]
fn comment_only() {
    let issues = analyze("-- just a comment", Some("postgresql"), Some("src/app.sql"));
    assert!(issues.is_empty(), "comment-only should produce no issues");
}

#[test]
fn select_constant() {
    let issues = analyze("SELECT 1", Some("postgresql"), Some("src/app.sql"));
    assert!(has_no_rule(&issues, "PERF-SCAN-003"), "SELECT 1 should not fire unbounded");
    assert!(has_no_rule(&issues, "COST-COMPUTE-001"), "SELECT 1 should not fire full scan");
}

#[test]
fn select_now() {
    let issues = analyze("SELECT NOW()", Some("postgresql"), None);
    assert!(has_no_rule(&issues, "PERF-SCAN-003"), "SELECT NOW() in adhoc should not fire");
}

#[test]
fn insert_into_logs_no_idempotency() {
    let issues = analyze(
        "INSERT INTO logs (message, created_at) VALUES ('event', NOW())",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"), "append-only table should skip idempotency");
}

#[test]
fn insert_into_audit_no_idempotency() {
    let issues = analyze(
        "INSERT INTO audit (action, user_id) VALUES ('login', 1)",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"), "audit table should skip idempotency");
}

#[test]
fn insert_into_user_event_mappings_needs_idempotency() {
    // Table name contains "event" but is NOT an append-only table
    let issues = analyze(
        "INSERT INTO user_event_mappings (user_id, event_id) VALUES (1, 2)",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "REL-IDEM-001"),
        "user_event_mappings should fire REL-IDEM-001 (not append-only)");
}

// ============================================================================
// CATEGORY 8: Dialect-specific rules respect dialect gates
// ============================================================================

#[test]
fn dialect_mysql_rule_on_postgresql_no_fire() {
    let issues = analyze(
        "INSERT IGNORE INTO users VALUES (1)",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-MYSQL-001"), "MySQL rule should not fire on PostgreSQL");
}

#[test]
fn dialect_mysql_rule_on_mysql_fires() {
    let issues = analyze(
        "INSERT IGNORE INTO users VALUES (1)",
        Some("mysql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "REL-MYSQL-001"), "MySQL rule should fire on MySQL");
}

#[test]
fn dialect_pg_sleep_on_mysql_no_fire() {
    let issues = analyze(
        "SELECT pg_sleep(5)",
        Some("mysql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-PG-001"), "PG rule should not fire on MySQL");
}

#[test]
fn dialect_tsql_tablock_on_postgresql_no_fire() {
    let issues = analyze(
        "SELECT * FROM t WITH (TABLOCK)",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-LOCK-001"), "TSQL rule should not fire on PostgreSQL");
}

// ============================================================================
// CATEGORY 9: Suppression system
// ============================================================================

#[test]
fn suppression_inline_specific() {
    let issues = analyze(
        "-- slowql: disable REL-DATA-001\nDELETE FROM users",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-DATA-001"), "suppressed rule should not fire");
    // Other rules should still fire
    assert!(has_rule(&issues, "PERF-SCAN-002"), "non-suppressed rule should still fire");
}

#[test]
fn suppression_inline_all() {
    let issues = analyze(
        "-- slowql: disable\nDELETE FROM users",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(issues.is_empty(), "all-suppressed should produce no issues");
}

// ============================================================================
// CATEGORY 10: Authorization precision
// ============================================================================

#[test]
fn authz_003_no_where_is_not_auth_bypass() {
    // SELECT * FROM orders with no WHERE is a full table scan, not auth bypass.
    // COST-COMPUTE-001 and PERF-SCAN-003 handle this.
    let issues = analyze(
        "SELECT * FROM orders",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-AUTHZ-003"),
        "no-WHERE query should not fire auth bypass (it is a full scan problem)");
    // But these should still fire:
    assert!(has_rule(&issues, "COST-COMPUTE-001"));
    assert!(has_rule(&issues, "PERF-SCAN-001"));
}

#[test]
fn authz_003_filtered_without_tenant_fires() {
    // SELECT with WHERE but no tenant scoping IS an authorization concern
    let issues = analyze(
        "SELECT * FROM orders WHERE status = 'pending'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_rule(&issues, "SEC-AUTHZ-003"),
        "filtered query on sensitive table without tenant scoping should fire");
}

#[test]
fn authz_003_filtered_with_tenant_no_fire() {
    let issues = analyze(
        "SELECT * FROM orders WHERE user_id = $1 AND status = 'pending'",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-AUTHZ-003"),
        "query with tenant scoping should not fire");
}

// ============================================================================
// CATEGORY 11: Real-world Rails/ORM patterns
// ============================================================================

#[test]
fn rails_drop_sequence_no_fire() {
    let issues = analyze(
        "DROP SEQUENCE IF EXISTS companies_id_seq",
        Some("postgresql"), Some("src/schema.sql")
    );
    assert!(has_no_rule(&issues, "REL-DATA-004"),
        "DROP SEQUENCE is maintenance, not data destruction");
}

#[test]
fn rails_drop_index_no_fire() {
    let issues = analyze(
        "DROP INDEX idx_users_email",
        Some("postgresql"), Some("src/schema.sql")
    );
    assert!(has_no_rule(&issues, "REL-DATA-004"),
        "DROP INDEX is maintenance, not data destruction");
}

#[test]
fn rails_drop_table_still_fires() {
    let issues = analyze(
        "DROP TABLE users",
        Some("postgresql"), Some("src/schema.sql")
    );
    assert!(has_rule(&issues, "REL-DATA-004"),
        "DROP TABLE must still fire");
}

#[test]
fn rails_drop_view_still_fires() {
    let issues = analyze(
        "DROP VIEW user_stats",
        Some("postgresql"), Some("src/schema.sql")
    );
    assert!(has_rule(&issues, "REL-DATA-004"),
        "DROP VIEW must still fire");
}

#[test]
fn rails_create_index_no_fk_warning() {
    let issues = analyze(
        "CREATE INDEX CONCURRENTLY idx_orders_user ON orders (user_id)",
        Some("postgresql"), Some("src/schema.sql")
    );
    assert!(has_no_rule(&issues, "QUAL-SCHEMA-002"),
        "CREATE INDEX should not fire missing FK warning");
}

#[test]
fn rails_create_table_with_fk_col_fires() {
    // Use application context path (not src/schema.sql which maps to ddl_schema context
    // where only SEC/REL/COMP rules are allowed)
    let issues = analyze(
        "CREATE TABLE replies (id INTEGER PRIMARY KEY, topic_id INTEGER, developer_id INTEGER)",
        Some("postgresql"), Some("src/queries.sql")
    );
    assert!(has_rule(&issues, "QUAL-SCHEMA-002"),
        "CREATE TABLE with _id columns without REFERENCES should fire");
}

#[test]
fn rails_bounded_join_no_authz() {
    let issues = analyze(
        "SELECT users.id, users.name FROM users INNER JOIN orders ON users.id = orders.user_id WHERE orders.created_at >= '2024-01-01' ORDER BY users.name LIMIT 100",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-AUTHZ-003"),
        "bounded JOIN query with LIMIT should not fire auth bypass");
}

#[test]
fn rails_orm_select_with_returning() {
    let issues = analyze(
        "UPDATE users SET updated_at = NOW() WHERE id = 1 RETURNING *",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-DATA-001"),
        "UPDATE with WHERE should not fire");
    assert!(has_no_rule(&issues, "PERF-SCAN-002"),
        "UPDATE with WHERE should not fire unbounded");
}

#[test]
fn rails_upsert_is_idempotent() {
    let issues = analyze(
        "INSERT INTO users (email, name) VALUES ('a@b.com', 'A') ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "REL-IDEM-001"),
        "UPSERT with ON CONFLICT is idempotent");
}

#[test]
fn rails_exists_check_no_issues() {
    let issues = analyze(
        "SELECT 1 AS one FROM users WHERE email = 'test@example.com' LIMIT 1",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-SCAN-003"), "EXISTS check with LIMIT should not fire");
    assert!(has_no_rule(&issues, "COST-COMPUTE-001"), "EXISTS check with WHERE should not fire");
}

#[test]
fn rails_count_with_where_no_issues() {
    let issues = analyze(
        "SELECT COUNT(*) FROM users WHERE active = true",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "PERF-AGG-001"), "filtered COUNT should not fire");
    assert!(has_no_rule(&issues, "COST-COMPUTE-001"), "filtered COUNT should not fire");
}

#[test]
fn rails_setval_no_issues() {
    let issues = analyze(
        "SELECT setval('accounts_id_seq', 100)",
        Some("postgresql"), Some("src/schema.sql")
    );
    assert!(has_no_rule(&issues, "PERF-SCAN-003"),
        "setval is a constant expression, not unbounded");
}

#[test]
fn rails_pragma_no_issues() {
    let issues = analyze(
        "PRAGMA defer_foreign_keys = ON",
        Some("sqlite"), Some("src/app.sql")
    );
    // PRAGMAs are admin commands, should not fire perf rules
    assert!(has_no_rule(&issues, "PERF-SCAN-003"));
    assert!(has_no_rule(&issues, "COST-COMPUTE-001"));
}

#[test]
fn rails_alter_table_enable_trigger_no_issues() {
    let issues = analyze(
        "ALTER TABLE users ENABLE TRIGGER ALL",
        Some("postgresql"), Some("src/schema.sql")
    );
    assert!(has_no_rule(&issues, "REL-DATA-003"),
        "ENABLE TRIGGER is not destructive ALTER");
}

#[test]
fn rails_pg_admin_query_no_issues() {
    let issues = analyze(
        "SELECT schemaname, tablename, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC",
        Some("postgresql"), Some("src/app.sql")
    );
    assert!(has_no_rule(&issues, "SEC-INFO-002"),
        "pg_stat query without dynamic signal should not fire");
}
