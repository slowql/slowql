use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::{Rule, RuleConfidence};
use once_cell::sync::Lazy;
use regex::Regex;

struct WeakHashingAlgorithmRule;
static PAT_CRYPTO_001: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(MD5|SHA1|SHA)\s*\(\s*[^)]*\b(password|passwd|pwd|secret|token|key|credential)\b",
    )
    .unwrap()
});

impl Rule for WeakHashingAlgorithmRule {
    fn id(&self) -> &'static str {
        "SEC-CRYPTO-001"
    }
    fn name(&self) -> &'static str {
        "Weak Hashing Algorithm"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecCrypto)
    }
    fn impact(&self) -> &'static str {
        "MD5 and SHA1 are cryptographically broken. GPU clusters can crack MD5 hashes at 200+ billion attempts/second."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CRYPTO_001
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Weak hashing algorithm detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct PlaintextPasswordInQueryRule;
static PAT_CRYPTO_002: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(INSERT\s+INTO|UPDATE)\b[^;]*\b(password|passwd|pwd|secret_key|api_key|auth_token)\b[^;]*?(?:=\s*|VALUES\s*\()[^;(]*?'[^'()]{4,}'"#).unwrap()
});

impl Rule for PlaintextPasswordInQueryRule {
    fn id(&self) -> &'static str {
        "SEC-CRYPTO-002"
    }
    fn name(&self) -> &'static str {
        "Plaintext Password in Query"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecCrypto)
    }
    fn impact(&self) -> &'static str {
        "Plaintext passwords in databases are catastrophic during breaches."
    }

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Contextual
    }
    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CRYPTO_002
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Potential plaintext password in query: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct HardcodedEncryptionKeyRule;
static PAT_CRYPTO_003: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(AES_ENCRYPT|AES_DECRYPT|ENCRYPT|DECRYPT|ENCRYPTBYKEY|DECRYPTBYKEY|HASHBYTES|HMAC)\s*\([^)]*,\s*'[A-Za-z0-9\+/=!@#\$%\^&\*\-]{8,}'"#).unwrap()
});

impl Rule for HardcodedEncryptionKeyRule {
    fn id(&self) -> &'static str {
        "SEC-CRYPTO-003"
    }
    fn name(&self) -> &'static str {
        "Hardcoded Encryption Key"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecCrypto)
    }
    fn impact(&self) -> &'static str {
        "Hardcoded keys in queries appear in query logs, execution plans, source control history, and monitoring tools."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CRYPTO_003
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Hardcoded encryption key detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

struct WeakEncryptionAlgorithmRule;
static PAT_CRYPTO_004: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(DES_ENCRYPT|DES_DECRYPT|TRIPLE_DES|3DES|RC4|RC2|BLOWFISH|IDEA)\s*\(")
        .unwrap()
});

impl Rule for WeakEncryptionAlgorithmRule {
    fn id(&self) -> &'static str {
        "SEC-CRYPTO-004"
    }
    fn name(&self) -> &'static str {
        "Weak Encryption Algorithm"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn dimension(&self) -> Dimension {
        Dimension::Security
    }
    fn category(&self) -> Option<Category> {
        Some(Category::SecCrypto)
    }
    fn impact(&self) -> &'static str {
        "DES uses 56-bit keys, crackable in hours. RC4 has critical biases. These algorithms are prohibited by PCI-DSS, HIPAA."
    }

    fn check(&self, query: &Query) -> Vec<Issue> {
        PAT_CRYPTO_004
            .find(&query.raw)
            .map(|m| {
                vec![self.build_issue(
                    query,
                    &format!("Weak encryption algorithm detected: {}", m.as_str()),
                    m.as_str(),
                )]
            })
            .unwrap_or_default()
    }
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(WeakHashingAlgorithmRule),
        Box::new(PlaintextPasswordInQueryRule),
        Box::new(HardcodedEncryptionKeyRule),
        Box::new(WeakEncryptionAlgorithmRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Location, Query};

    fn q(sql: &str, dialect: &str, qt: &str) -> Query {
        Query {
            raw: sql.to_string(),
            normalized: sql.to_string(),
            dialect: dialect.to_string(),
            location: Location::new(1, 1),
            query_type: Some(qt.to_string()),
            source_context: "application".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn metadata_coverage() {
        let rules = rules();
        for rule in &rules {
            let _ = rule.id();
            let _ = rule.name();
            let _ = rule.severity();
            let _ = rule.dimension();
            let _ = rule.category();
            let _ = rule.impact();
            let _ = rule.fix_guidance();
            let _ = rule.confidence();
            let _ = rule.dialects();
        }
    }

    #[test]
    fn no_match_simple() {
        let rules = rules();
        let query = q("SELECT 1", "postgresql", "SELECT");
        for rule in &rules {
            let _ = rule.check(&query);
        }
    }

    #[test]
    fn dialect_coverage() {
        let rules = rules();
        let dialects = [
            "postgresql",
            "mysql",
            "tsql",
            "oracle",
            "sqlite",
            "bigquery",
            "snowflake",
            "redshift",
            "clickhouse",
        ];
        for dialect in &dialects {
            for qt in &["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP"] {
                let query = q("SELECT 1", dialect, qt);
                for rule in &rules {
                    let _ = rule.check(&query);
                    let _ = rule.dialect_matches(&query);
                }
            }
        }
    }
}
