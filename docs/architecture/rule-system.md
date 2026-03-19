# Rule System

SlowQL separates logical rules from its execution framework. This enables absolute code decoupling where adding a new check logic is simply a matter of tossing a subclass into the respective directory.

## Analysers vs. Rules

The system is fundamentally categorized into two domains:

1. **Analyzers**: Represent rigid, logical dimensions (`SecurityAnalyzer`, `CostAnalyzer`, `PerformanceAnalyzer`). These classes subclass `RuleBasedAnalyzer` or `CompositeAnalyzer`. Their absolute truth is to be discovered and registered dynamically when the engine boots via `AnalyzerRegistry` (utilizing python entry points `slowql.analyzers`).
2. **Rules**: Individual logic gates enforcing a single static condition (`SelectStarRule`, `DropTableWithoutTransactionRule`).

## Rule Classes

All rules must be declared universally in `src/slowql/rules/<dimension>/` and inherent the `Rule` foundation class. 
The foundation forces the presence of rule metadata (the `id`, `name`, `severity`, `dimension` `dialects`, `impact`, and `fix_guidance`). 

When defining custom checks, you choose one of two distinct subclasses:

### 1. `PatternRule`
A high-performance pattern matcher completely ignoring the `sqlglot` AST infrastructure. 

Instead of an AST context, it leans on compiled Regular Expressions (`self.pattern`) or raw tokenizer scanning (`self.check(query)` checking against `query.raw` tokens). Highly efficient, but only robust on simplistic edge cases where the query format isn't ambiguous.

### 2. `ASTRule`
The most commonly registered object in SlowQL. Instead of string matching, it natively analyzes the pre-parsed `exp.Expression` tree constructed by `UniversalParser`. 

By iterating via `ast.find_all(exp.Select)`, it guarantees zero false positives from syntax nested inside subqueries, string literals, or single-line comments.

## Safe Autofixes

Because SlowQL guarantees high execution safety, many default rules are marked with `RemediationMode.SAFE_APPLY` inside their class definition.

Through implementing a `suggest_fix(self, query: Query) -> Fix` method, a Rule can yield an explicit textual diff patch (`original` vs `replacement`) coupled with a `FixConfidence` assertion (typically `FixConfidence.SAFE`).

If the user initiates `slowql --fix`, the Engine compiles these `Fix` objects across all queries to rewrite the script programmatically while caching backups, completely automating the SQL engineering effort.
