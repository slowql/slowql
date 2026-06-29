# Rule System

SlowQL rules are implemented as Rust structs that implement the `Rule` trait.

## Rule Trait

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn dimension(&self) -> Dimension;

    fn confidence(&self) -> RuleConfidence {
        RuleConfidence::Proven  // default
    }

    fn category(&self) -> Option<Category> { None }
    fn dialects(&self) -> DialectSet { DialectSet::universal() }
    fn impact(&self) -> &'static str { "" }
    fn fix_guidance(&self) -> Option<&'static str> { None }

    fn check(&self, query: &Query) -> Vec<Issue>;
}
```

## Confidence Levels

| **Level** | **Value** | **Description** |
|-----------|-----------|-----------------|
| `Proven` | 3 | Structurally deterministic. Zero false positives. Default. |
| `Contextual` | 2 | Accurate with context. May need verification. |
| `Advisory` | 1 | Style hint or best practice. Not provably wrong. |

Confidence levels are ordered. `proven > contextual > advisory`. The `--min-confidence` flag filters by this order.

## RuleContext
Rules receive a `RuleContext` alongside each query:

```rust
pub struct RuleContext<'a> {
    pub schema: Option<&'a Schema>,
    pub table_metadata: &'a HashMap<String, TableMetadata>,
    pub source_context: &'a str,
}
```
Rules can use this to:
- Check if a table exists in the schema
- Check if a table is marked as large or partitioned
- Adjust behavior based on file context

## Dialect Filtering
Rules declare which dialects they apply to via `dialects()`. Universal rules return `DialectSet::universal()`. Dialect-specific rules return `DialectSet::new(&["postgresql"])`.

The engine skips rules that do not match the query's dialect.

## Issue Building
Rules use `build_issue()` to create issues consistently:
``` Rust
fn check(&self, query: &Query) -> Vec<Issue> {
    if query.raw_upper().contains("DANGEROUS_PATTERN") {
        return vec![self.build_issue(
            query,
            "Dangerous pattern found",
            query.snippet(80),  // always use snippet(), never raw slicing
        )];
    }
    Vec::new()
}
```

## Rule Dimensions
| **Dimension** | **Prefix** | **Count** |
|---------------|------------|-----------|
| Security      | `SEC-`       | 61        |
| Performance   | `PERF-`      | 73        |
| Reliability   | `REL-`       | 44        |
| Quality       | `QUAL-`      | 52        |
| Cost          | `COST-`      | 33        |
| Compliance    | `COMP-`      | 18        |
| Migration     | `MIG-`       | 2         |
| Schema        | `SCHEMA-`    | 2         |

## Custom YAML Rules
Users can define rules without modifying source code:
``` YAML
rules:
  - id: ORG-001
    name: "Require tenant_id"
    severity: high
    dimension: security
    pattern: "SELECT.*FROM\\s+orders\\b(?!.*tenant_id)"
    message: "All queries on orders must filter by tenant_id"
```
YAML rules support:
- Regex patterns
- Severity and dimension
- Custom messages with `{match}` placeholder
- Dialect filtering
