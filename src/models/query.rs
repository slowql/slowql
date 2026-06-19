use serde::{Deserialize, Serialize};
use crate::models::issue::Location;
use std::cell::OnceCell;

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
    /// Parsed structural facts (lazily populated by engine).
    #[serde(skip)]
    pub facts: Option<crate::query_analysis::QueryFacts>,
    /// Cached uppercase version. Computed lazily, not serialized.
    #[serde(skip)]
    #[serde(default)]
    pub raw_upper_cache: OnceCell<String>,
    /// Cached lowercase version. Computed lazily, not serialized.
    #[serde(skip)]
    #[serde(default)]
    pub raw_lower_cache: OnceCell<String>,
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

    /// Returns the uppercase version of raw SQL. Cached after first call.
    pub fn raw_upper(&self) -> &str {
        self.raw_upper_cache.get_or_init(|| self.raw.to_uppercase())
    }

    /// Returns the lowercase version of raw SQL. Cached after first call.
    pub fn raw_lower(&self) -> &str {
        self.raw_lower_cache.get_or_init(|| self.raw.to_lowercase())
    }

    pub fn has_keyword(&self, keyword: &str) -> bool {
        self.raw_upper().contains(&keyword.to_uppercase())
    }

    /// Snip the first N bytes of raw SQL (safe for display).
    pub fn snippet(&self, max_len: usize) -> &str {
        &self.raw[..self.raw.len().min(max_len)]
    }

    /// Returns true if this query contains format placeholders or
    /// string interpolation markers that indicate it is a template,
    /// not concrete executable SQL.
    pub fn is_templated(&self) -> bool {
        let raw = &self.raw;
        // Python-style: %(name)s, %s, %d, %f
        if raw.contains("%(") || raw.contains("%s") || raw.contains("%d") {
            return true;
        }
        // Django double-percent escaping: %%s
        if raw.contains("%%s") || raw.contains("%%d") {
            return true;
        }
        // Ruby/Rails interpolation: #{expr}
        if raw.contains("#{") {
            return true;
        }
        // Go template syntax: {{ .Ident }}
        if raw.contains("{{") && raw.contains("}}") {
            return true;
        }
        // JavaScript/TypeScript template literals: ${expr}
        if raw.contains("${") {
            return true;
        }
        // Python str.format / f-string style: {name}, {}, {TABLE_NAME}, etc.
        if raw.contains('{') && raw.contains('}')
            && !raw.contains("${") && !raw.contains("#{") {
            let upper = self.raw_upper();
            // Skip actual SQL blocks that use {} (PL/pgSQL, DO $$)
            if !upper.contains("BEGIN") && !upper.contains("$$")
                && !upper.contains("JSONB") {
                let bytes = raw.as_bytes();
                for i in 0..bytes.len().saturating_sub(1) {
                    if bytes[i] == b'{' {
                        let next = bytes[i + 1];
                        // {} or {identifier}
                        if next == b'}' || next.is_ascii_alphabetic() || next == b'_' {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}

impl Default for Query {
    fn default() -> Self {
        Query {
            raw: String::new(),
            normalized: String::new(),
            dialect: String::new(),
            location: Location::new(1, 1),
            start_offset: None,
            end_offset: None,
            tables: Vec::new(),
            columns: Vec::new(),
            query_type: None,
            is_ddl: false,
            is_dynamic: false,
            complexity_score: 0,
            source_context: String::new(),
            facts: None,
            raw_upper_cache: OnceCell::new(),
            raw_lower_cache: OnceCell::new(),
        }
    }
}
