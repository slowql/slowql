use crate::models::issue::Category;
use crate::models::{Dimension, Issue, Query, Severity};
use crate::rules::base::Rule;
use once_cell::sync::Lazy;
use regex::Regex;

// COMP-GDPR-001
struct PiiExposureRule;
static PAT_PII: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(email|ssn|social_security|credit_card|cc_num|passport)\b").unwrap());
impl Rule for PiiExposureRule { fn id(&self) -> &'static str { "COMP-GDPR-001" } fn name(&self) -> &'static str { "Potential PII Selection" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompGdpr) } fn impact(&self) -> &'static str { "Accessing PII requires audit logging and strict access controls under GDPR/CCPA." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_PII.find(&query.raw).map(|m| { let msg = format!("Potential PII column accessed: {}", m.as_str()); vec![self.build_issue(query, &msg, m.as_str())] }).unwrap_or_default() } }

// COMP-GDPR-002
struct CrossBorderDataTransferRule;
static PAT_CROSS_BORDER: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(\bDBLINK\s*\()|(\bOPENROWSET\s*\()|(\bCREATE\s+SERVER\b)|(\bCREATE\s+FOREIGN\s+TABLE\b)").unwrap());
impl Rule for CrossBorderDataTransferRule { fn id(&self) -> &'static str { "COMP-GDPR-002" } fn name(&self) -> &'static str { "Potential Cross-Border Data Transfer" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompGdpr) } fn impact(&self) -> &'static str { "Transferring personal data to foreign servers without safeguards violates GDPR Chapter V." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_CROSS_BORDER.find(&query.raw).map(|m| { let msg = format!("Cross-database or foreign data access detected: {}", m.as_str()); vec![self.build_issue(query, &msg, m.as_str())] }).unwrap_or_default() } }

// COMP-GDPR-003
struct RightToErasureRule;
static PAT_ERASURE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bDELETE\s+FROM\s+(users|customers|accounts|profiles|members|user_data|customer_data|personal_data)\b").unwrap());
impl Rule for RightToErasureRule { fn id(&self) -> &'static str { "COMP-GDPR-003" } fn name(&self) -> &'static str { "Right to Erasure Check" } fn severity(&self) -> Severity { Severity::Info } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompGdpr) } fn impact(&self) -> &'static str { "Incomplete erasure leaves PII in related tables, violating GDPR Article 17." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_ERASURE.find(&query.raw).map(|m| { let msg = format!("DELETE on PII table detected - verify GDPR erasure completeness: {}", m.as_str()); vec![self.build_issue(query, &msg, m.as_str())] }).unwrap_or_default() } }

// COMP-GDPR-004
struct ConsentTableMissingRule;
static PAT_MARKETING: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bINSERT\s+INTO\s+\w*(marketing|newsletter|mailing_list|campaign|subscribers|email_list)\w*\b").unwrap());
impl Rule for ConsentTableMissingRule { fn id(&self) -> &'static str { "COMP-GDPR-004" } fn name(&self) -> &'static str { "Marketing Insert Without Consent Signal" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompGdpr) } fn impact(&self) -> &'static str { "Adding users to marketing lists without consent violates GDPR Article 7." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_MARKETING.find(&query.raw).map(|m| { let msg = format!("INSERT into marketing table - verify GDPR consent: {}", m.as_str()); vec![self.build_issue(query, &msg, m.as_str())] }).unwrap_or_default() } }

// COMP-GDPR-005
struct DataExportCompletenessRule;
impl Rule for DataExportCompletenessRule { fn id(&self) -> &'static str { "COMP-GDPR-005" } fn name(&self) -> &'static str { "Data Subject Request Without Completeness Check" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompGdpr) } fn impact(&self) -> &'static str { "Incomplete DSAR responses violate GDPR Article 15." } fn check(&self, query: &Query) -> Vec<Issue> { if !query.is_select() { return Vec::new(); } let lower = query.raw_lower(); if !lower.contains("export") && !lower.contains("dsar") && !lower.contains("access_request") && !lower.contains("subject_data") { return Vec::new(); } if lower.contains("users") && !lower.contains("activity_log") && !lower.contains("user_log") && !lower.contains("audit_log") { return vec![self.build_issue(query, "User data export might be missing related audit or activity logs.", query.snippet(100))]; } Vec::new() } }

// COMP-GDPR-006
struct ConsentWithdrawalRule;
static PII_TABLES: &[&str] = &["users","profiles","customers","contacts","leads"];
static CONSENT_COLS: &[&str] = &["consent","consent_status","opt_in","active"];
impl Rule for ConsentWithdrawalRule { fn id(&self) -> &'static str { "COMP-GDPR-006" } fn name(&self) -> &'static str { "Consent Withdrawal Not Honored" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompGdpr) } fn impact(&self) -> &'static str { "Failing to honor consent withdrawal violates GDPR Article 7." } fn check(&self, query: &Query) -> Vec<Issue> { if !query.is_select() { return Vec::new(); }
        let lower = query.raw_lower();
        let hits_pii = PII_TABLES.iter().any(|t| lower.contains(t));
        if !hits_pii { return Vec::new(); }
        let pii_cols = ["email","phone","ssn","address","date_of_birth","social_security","credit_card","first_name","last_name","passport","national_id","name"];
        let accesses_pii = if let Some(ref facts) = query.facts {
            facts.selects_star || pii_cols.iter().any(|c| facts.selects_column(c))
        } else {
            query.raw_upper().contains("SELECT *") || pii_cols.iter().any(|c| lower.contains(c))
        };
        if !accesses_pii { return Vec::new(); }
        let has_consent = CONSENT_COLS.iter().any(|c| lower.contains(c));
        if has_consent { return Vec::new(); }
        vec![self.build_issue(query, "PII access without active consent filter.", query.snippet(100))] } }

// COMP-HIPAA-001
struct PhiAccessWithoutAuditRule;
static PHI_TABLES: &[&str] = &["patients","patient","medical_records","diagnoses","prescriptions","treatments","procedures","lab_results","radiology","encounters","visits","admissions","insurance_claims","billing_records","health_records","clinical_data","ehr","emr"];
static PHI_COLS: &[&str] = &["ssn","social_security","mrn","medical_record_number","diagnosis","condition","medication","prescription","treatment","procedure","lab_result","test_result","health_status","patient_id","member_id"];
impl Rule for PhiAccessWithoutAuditRule { fn id(&self) -> &'static str { "COMP-HIPAA-001" } fn name(&self) -> &'static str { "PHI Access Without Audit Trail" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompHipaa) } fn impact(&self) -> &'static str { "Lack of audit trails for PHI access violates HIPAA Technical Safeguards." } fn check(&self, query: &Query) -> Vec<Issue> { let lower = query.raw_lower(); let is_phi = PHI_TABLES.iter().any(|t| lower.contains(t)) || PHI_COLS.iter().any(|c| lower.contains(c)); if !is_phi { return Vec::new(); } if lower.contains("audit") || lower.contains("access_log") || lower.contains("phi_log") || lower.contains("compliance_log") { return Vec::new(); } vec![self.build_issue(query, "PHI access detected without apparent audit logging reference.", query.snippet(100))] } }

// COMP-HIPAA-002
struct PhiMinimumNecessaryRule;
impl Rule for PhiMinimumNecessaryRule { fn id(&self) -> &'static str { "COMP-HIPAA-002" } fn name(&self) -> &'static str { "PHI Minimum Necessary Violation" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompHipaa) } fn impact(&self) -> &'static str { "Fetching all columns from healthcare tables retrieves unnecessary PHI." } fn check(&self, query: &Query) -> Vec<Issue> { if !query.is_select() { return Vec::new(); } let upper = query.raw_upper(); if !upper.contains("SELECT *") { return Vec::new(); } let lower = query.raw_lower(); if PHI_TABLES.iter().any(|t| lower.contains(t)) { return vec![self.build_issue(query, "SELECT * on PHI table - violates Minimum Necessary standard.", "SELECT *")]; } Vec::new() } }

// COMP-HIPAA-003
struct UnencryptedPhiTransitRule;
static PAT_UNENC_PHI: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(encrypt=false|trustServerCertificate=true|sslmode=disable|ssl_mode=none)\b.*?\b(patients|medical_records|phi|health|ehr)\b").unwrap());
impl Rule for UnencryptedPhiTransitRule { fn id(&self) -> &'static str { "COMP-HIPAA-003" } fn name(&self) -> &'static str { "Unencrypted PHI Transit Signal" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompHipaa) } fn impact(&self) -> &'static str { "Transmitting PHI over unencrypted connections violates HIPAA Security Rule." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_UNENC_PHI.find(&query.raw).map(|m| vec![self.build_issue(query, "Insecure connection parameters for PHI-related database.", m.as_str())]).unwrap_or_default() } }

// COMP-PCI-001
struct PanExposureRule;
static PAT_PAN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b").unwrap());
impl Rule for PanExposureRule { fn id(&self) -> &'static str { "COMP-PCI-001" } fn name(&self) -> &'static str { "PAN Exposure in SQL" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompPci) } fn impact(&self) -> &'static str { "Unmasked PANs in logs or application output violate PCI-DSS." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_PAN.find(&query.raw).map(|m| { let msg = format!("Potential unmasked PAN detected: {}", m.as_str()); vec![self.build_issue(query, &msg, m.as_str())] }).unwrap_or_default() } }

// COMP-PCI-002
struct CvvStorageRule;
static PAT_CVV: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(INSERT|CREATE)\b.*?\b(cvv|cvc|cid|security_code|card_verification)\b").unwrap());
impl Rule for CvvStorageRule { fn id(&self) -> &'static str { "COMP-PCI-002" } fn name(&self) -> &'static str { "CVV Storage Violation" } fn severity(&self) -> Severity { Severity::Critical } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompPci) } fn impact(&self) -> &'static str { "Storing CVV/CVC is a major PCI-DSS violation." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_CVV.find(&query.raw).map(|m| { let msg = format!("Illegal storage of sensitive authentication data (CVV/CVC): {}", m.as_str()); vec![self.build_issue(query, &msg, m.as_str())] }).unwrap_or_default() } }

// COMP-PCI-003
struct CardholderDataRetentionRule;
static PAT_CARDHOLDER: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bSELECT\b.*?\bFROM\b.*?\b(transactions|cardholder_data|payments)\b").unwrap());
impl Rule for CardholderDataRetentionRule { fn id(&self) -> &'static str { "COMP-PCI-003" } fn name(&self) -> &'static str { "Data Retention Violation" } fn severity(&self) -> Severity { Severity::Medium } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompPci) } fn impact(&self) -> &'static str { "Keeping cardholder data longer than necessary increases risk." } fn check(&self, query: &Query) -> Vec<Issue> { if let Some(m) = PAT_CARDHOLDER.find(&query.raw) { let lower = query.raw_lower(); if !lower.contains("date") && !lower.contains("created_at") && !lower.contains("timestamp") && !lower.contains("retention") { return vec![self.build_issue(query, "Query on cardholder data without time-based filter.", m.as_str())]; } } Vec::new() } }

// COMP-SEC-001
struct UnencryptedSensitiveColumnRule;
static PAT_UNENC_COL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCREATE\s+TABLE\b.+\b(password|secret|token|ssn|credit_card|cvv|pin)\b.+\b(VARCHAR|TEXT|CHAR)\b").unwrap());
impl Rule for UnencryptedSensitiveColumnRule { fn id(&self) -> &'static str { "COMP-SEC-001" } fn name(&self) -> &'static str { "Unencrypted Sensitive Column Definition" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompPci) } fn impact(&self) -> &'static str { "Storing sensitive values in plain text violates PCI-DSS, HIPAA, and GDPR." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_UNENC_COL.find(&query.raw).map(|m| vec![self.build_issue(query, "Sensitive column defined with plain text type - consider encryption.", m.as_str())]).unwrap_or_default() } }

// COMP-RET-001
struct RetentionPolicyMissingRule;
static PAT_RETENTION: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bCREATE\s+TABLE\b.+\b(audit|audits|audit_log|event_log|history|logs|access_log|activity_log)\b").unwrap());
impl Rule for RetentionPolicyMissingRule { fn id(&self) -> &'static str { "COMP-RET-001" } fn name(&self) -> &'static str { "Missing Retention Policy Signal" } fn severity(&self) -> Severity { Severity::Low } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompGdpr) } fn impact(&self) -> &'static str { "Indefinite retention of audit data violates GDPR storage limitation." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_RETENTION.find(&query.raw).map(|m| vec![self.build_issue(query, "Table with audit/log naming - verify retention policy exists.", m.as_str())]).unwrap_or_default() } }

// COMP-AUD-001
struct AuditLogTamperingRule;
static PAT_AUDIT_TAMP: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(DELETE\s+FROM|UPDATE)\s+\w*(audit|audit_log|event_log|access_log|activity_log|audit_trail|system_log)\w*\b").unwrap());
impl Rule for AuditLogTamperingRule { fn id(&self) -> &'static str { "COMP-AUD-001" } fn name(&self) -> &'static str { "Audit Log Tampering Risk" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompSox) } fn impact(&self) -> &'static str { "Modifying audit logs violates regulatory non-repudiation requirements." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_AUDIT_TAMP.find(&query.raw).map(|m| vec![self.build_issue(query, "Modification of audit/log table detected - potential compliance violation.", m.as_str())]).unwrap_or_default() } }

// COMP-SOX-001
struct FinancialChangeTrackingRule;
static FIN_TABLES: &[&str] = &["ledger","accounts","payments","salaries","payroll","revenue","expenses","general_ledger","trial_balance","balance_sheet"];
impl Rule for FinancialChangeTrackingRule { fn id(&self) -> &'static str { "COMP-SOX-001" } fn name(&self) -> &'static str { "Financial Data Modification Without Change Tracking" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompSox) } fn impact(&self) -> &'static str { "Untracked modifications to financial records violate SOX Section 404 internal controls." } fn check(&self, query: &Query) -> Vec<Issue> { let qt = query.query_type.as_deref().unwrap_or(""); if qt != "UPDATE" && qt != "DELETE" { return Vec::new(); } let lower = query.raw_lower(); if !FIN_TABLES.iter().any(|t| lower.contains(t)) { return Vec::new(); } let has_tracking = ["ticket","req","reason","change_id","ref","bug","jira"].iter().any(|k| lower.contains(k)); if has_tracking { return Vec::new(); } vec![self.build_issue(query, "Financial data modification without change tracking reference.", query.snippet(100))] } }

// COMP-SOX-002
struct SegregationOfDutiesRule;
static PAT_SOD: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bUPDATE\s+.*?\bSET\s+.*?\b(approved_by|status)\b.*?\bWHERE\b.*?\bcreated_by\b").unwrap());
impl Rule for SegregationOfDutiesRule { fn id(&self) -> &'static str { "COMP-SOX-002" } fn name(&self) -> &'static str { "Segregation of Duties Violation" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompSox) } fn impact(&self) -> &'static str { "SoD violations allow a single individual to initiate and approve financial transactions." } fn check(&self, query: &Query) -> Vec<Issue> { PAT_SOD.find(&query.raw).map(|m| vec![self.build_issue(query, "Potential Segregation of Duties violation: user approving their own creation.", m.as_str())]).unwrap_or_default() } }

// COMP-CCPA-001
struct CcpaOptOutRule;
impl Rule for CcpaOptOutRule { fn id(&self) -> &'static str { "COMP-CCPA-001" } fn name(&self) -> &'static str { "Do Not Sell Flag Not Checked" } fn severity(&self) -> Severity { Severity::High } fn dimension(&self) -> Dimension { Dimension::Compliance } fn category(&self) -> Option<Category> { Some(Category::CompCcpa) } fn impact(&self) -> &'static str { "Processing sale of data for opted-out consumers violates CCPA." } fn check(&self, query: &Query) -> Vec<Issue> { if !query.is_select() { return Vec::new(); } let lower = query.raw_lower(); if !lower.contains("marketing") && !lower.contains("sharing") && !lower.contains("third_party") && !lower.contains("affiliate") { return Vec::new(); } let has_dns = ["do_not_sell","dns_flag","opt_out","ccpa_status"].iter().any(|c| lower.contains(c)); if has_dns { return Vec::new(); } vec![self.build_issue(query, "Data share/sale query without CCPA Do Not Sell flag check.", query.snippet(100))] } }

pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(PiiExposureRule), Box::new(CrossBorderDataTransferRule),
        Box::new(RightToErasureRule), Box::new(ConsentTableMissingRule),
        Box::new(DataExportCompletenessRule), Box::new(ConsentWithdrawalRule),
        Box::new(PhiAccessWithoutAuditRule), Box::new(PhiMinimumNecessaryRule),
        Box::new(UnencryptedPhiTransitRule),
        Box::new(PanExposureRule), Box::new(CvvStorageRule), Box::new(CardholderDataRetentionRule),
        Box::new(UnencryptedSensitiveColumnRule), Box::new(RetentionPolicyMissingRule),
        Box::new(AuditLogTamperingRule),
        Box::new(FinancialChangeTrackingRule), Box::new(SegregationOfDutiesRule),
        Box::new(CcpaOptOutRule),
    ]
}
