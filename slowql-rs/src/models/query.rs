use serde::{Deserialize, Serialize};
use crate::models::issue::Location;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    pub raw: String,
    pub normalized: String,
    pub dialect: String,
    pub location: Location,
    pub start_offset: Option<usize>,
    pub end_offset: Option<usize>,
    pub tables: Vec<String>,
    pub columns: Vec<String>,
    pub query_type: Option<String>,
    pub is_ddl: bool,
    pub is_dynamic: bool,
    pub complexity_score: u32,
    pub source_context: String,
}

impl Query {
    pub fn is_select(&self) -> bool {
        self.query_type.as_deref().map(|t| t.eq_ignore_ascii_case("SELECT")).unwrap_or(false)
    }

    pub fn is_insert(&self) -> bool {
        self.query_type.as_deref().map(|t| t.eq_ignore_ascii_case("INSERT")).unwrap_or(false)
    }

    pub fn is_update(&self) -> bool {
        self.query_type.as_deref().map(|t| t.eq_ignore_ascii_case("UPDATE")).unwrap_or(false)
    }

    pub fn is_delete(&self) -> bool {
        self.query_type.as_deref().map(|t| t.eq_ignore_ascii_case("DELETE")).unwrap_or(false)
    }

    pub fn raw_upper(&self) -> String {
        self.raw.to_uppercase()
    }

    pub fn has_keyword(&self, keyword: &str) -> bool {
        let upper = self.raw_upper();
        let kw = keyword.to_uppercase();
        upper.contains(&kw)
    }
}
