use slowql_lib::models::{Location, Query};
use slowql_lib::rules::{migration, schema};

fn q(sql: &str, qt: &str) -> Query {
    Query {
        raw: sql.to_string(),
        normalized: sql.to_string(),
        dialect: "postgresql".to_string(),
        location: Location::new(1, 1),
        start_offset: None,
        end_offset: None,
        tables: vec![],
        columns: vec![],
        query_type: Some(qt.to_string()),
        is_ddl: true,
        is_dynamic: false,
        complexity_score: 0,
        source_context: String::new(),
        ..Default::default()
    }
}

#[test]
fn schema_count() {
    assert_eq!(schema::all_rules().len(), 4);
}
#[test]
fn migration_count() {
    assert_eq!(migration::all_rules().len(), 1);
}
#[test]
fn mig_drop_table() {
    let r = migration::all_rules();
    assert_eq!(r[0].check(&q("DROP TABLE users", "DROP")).len(), 1);
}
#[test]
fn mig_drop_column() {
    let r = migration::all_rules();
    assert_eq!(
        r[0].check(&q("ALTER TABLE users DROP COLUMN email", "ALTER"))
            .len(),
        1
    );
}
#[test]
fn mig_safe_alter() {
    let r = migration::all_rules();
    assert_eq!(
        r[0].check(&q(
            "ALTER TABLE users ADD COLUMN phone VARCHAR(20)",
            "ALTER"
        ))
        .len(),
        0
    );
}
