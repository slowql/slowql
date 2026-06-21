use slowql_lib::models::{Location, Query};
use slowql_lib::rules::compliance;
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
        source_context: "application".to_string(),
        ..Default::default()
    }
}
fn find<'a>(rules: &'a [Box<dyn Rule>], id: &str) -> &'a dyn Rule {
    rules
        .iter()
        .find(|r| r.id() == id)
        .map(|r| r.as_ref())
        .unwrap_or_else(|| panic!("rule {} not found", id))
}
fn all() -> Vec<Box<dyn Rule>> {
    compliance::all_rules()
}

#[test]
fn compliance_rule_count() {
    assert_eq!(all().len(), 18);
}

#[test]
fn gdpr_001_pii() {
    let r = all();
    let rule = find(&r, "COMP-GDPR-001");
    assert!(!rule
        .check(&q("SELECT email FROM users", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT id FROM users", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn gdpr_002_cross_border() {
    let r = all();
    let rule = find(&r, "COMP-GDPR-002");
    assert!(!rule
        .check(&q(
            "SELECT DBLINK('host=remote', 'SELECT 1')",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT 1", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn gdpr_003_erasure() {
    let r = all();
    let rule = find(&r, "COMP-GDPR-003");
    assert!(!rule
        .check(&q("DELETE FROM users WHERE id=1", "postgresql", "DELETE"))
        .is_empty());
    assert!(rule
        .check(&q(
            "DELETE FROM settings WHERE id=1",
            "postgresql",
            "DELETE"
        ))
        .is_empty());
}
#[test]
fn gdpr_004_consent() {
    let r = all();
    let rule = find(&r, "COMP-GDPR-004");
    assert!(!rule
        .check(&q(
            "INSERT INTO newsletter_subscribers VALUES (1,'a@b.com')",
            "postgresql",
            "INSERT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("INSERT INTO orders VALUES (1)", "postgresql", "INSERT"))
        .is_empty());
}
#[test]
fn gdpr_006_consent_withdrawal() {
    let r = all();
    let rule = find(&r, "COMP-GDPR-006");
    assert!(!rule
        .check(&q("SELECT * FROM users", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM users WHERE consent_status = 'active'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM settings", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn hipaa_001_phi_audit() {
    let r = all();
    let rule = find(&r, "COMP-HIPAA-001");
    assert!(!rule
        .check(&q(
            "SELECT * FROM patients WHERE id=1",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM patients p JOIN audit_log a ON p.id=a.patient_id",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM orders", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn hipaa_002_minimum_necessary() {
    let r = all();
    let rule = find(&r, "COMP-HIPAA-002");
    assert!(!rule
        .check(&q("SELECT * FROM patients", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q("SELECT name FROM patients", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn pci_001_pan() {
    let r = all();
    let rule = find(&r, "COMP-PCI-001");
    assert!(!rule
        .check(&q(
            "INSERT INTO t VALUES ('4111111111111111')",
            "postgresql",
            "INSERT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "INSERT INTO t VALUES ('not a card')",
            "postgresql",
            "INSERT"
        ))
        .is_empty());
}
#[test]
fn pci_002_cvv() {
    let r = all();
    let rule = find(&r, "COMP-PCI-002");
    assert!(!rule
        .check(&q(
            "INSERT INTO cards (cvv) VALUES ('123')",
            "postgresql",
            "INSERT"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "INSERT INTO cards (name) VALUES ('John')",
            "postgresql",
            "INSERT"
        ))
        .is_empty());
}
#[test]
fn pci_003_retention() {
    let r = all();
    let rule = find(&r, "COMP-PCI-003");
    assert!(!rule
        .check(&q("SELECT * FROM transactions", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM transactions WHERE created_at > '2024-01-01'",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
}
#[test]
fn sec_001_unencrypted() {
    let r = all();
    let rule = find(&r, "COMP-SEC-001");
    assert!(!rule
        .check(&q(
            "CREATE TABLE t (password VARCHAR(255))",
            "postgresql",
            "CREATE"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "CREATE TABLE t (name VARCHAR(255))",
            "postgresql",
            "CREATE"
        ))
        .is_empty());
}
#[test]
fn ret_001_retention() {
    let r = all();
    let rule = find(&r, "COMP-RET-001");
    assert!(!rule
        .check(&q(
            "CREATE TABLE audit_log (id INT)",
            "postgresql",
            "CREATE"
        ))
        .is_empty());
    assert!(rule
        .check(&q("CREATE TABLE orders (id INT)", "postgresql", "CREATE"))
        .is_empty());
}
#[test]
fn aud_001_tampering() {
    let r = all();
    let rule = find(&r, "COMP-AUD-001");
    assert!(!rule
        .check(&q(
            "DELETE FROM audit_log WHERE id=1",
            "postgresql",
            "DELETE"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM audit_log", "postgresql", "SELECT"))
        .is_empty());
}
#[test]
fn sox_001_financial() {
    let r = all();
    let rule = find(&r, "COMP-SOX-001");
    assert!(!rule
        .check(&q(
            "UPDATE ledger SET amount=0 WHERE id=1",
            "postgresql",
            "UPDATE"
        ))
        .is_empty());
    assert!(rule
        .check(&q(
            "UPDATE ledger SET amount=0 WHERE id=1 -- ticket: JIRA-123",
            "postgresql",
            "UPDATE"
        ))
        .is_empty());
    assert!(rule
        .check(&q("UPDATE settings SET val=1", "postgresql", "UPDATE"))
        .is_empty());
}
#[test]
fn ccpa_001_opt_out() {
    let r = all();
    let rule = find(&r, "COMP-CCPA-001");
    assert!(!rule
        .check(&q("SELECT * FROM marketing_data", "postgresql", "SELECT"))
        .is_empty());
    assert!(rule
        .check(&q(
            "SELECT * FROM marketing_data WHERE do_not_sell = false",
            "postgresql",
            "SELECT"
        ))
        .is_empty());
    assert!(rule
        .check(&q("SELECT * FROM orders", "postgresql", "SELECT"))
        .is_empty());
}
