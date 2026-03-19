# Python API Reference

SlowQL fundamentally exposes a deeply typed Python API for programmatic integration, establishing the groundwork required to build custom linting pipelines, embed rules into backend servers, or trigger standalone validations directly without initializing sub-processes.

## 1. Engine Instantiation

The `Engine` module completely manages rule compilation pipelines, hardware parallelization, and output serializers.

### Basic Offline Analysis

```python
from slowql.core.engine import Engine
from slowql.core.config import Config

# Initialize engine binding to localized overrides inside slowql.yaml or Environment definitions
config = Config.find_and_load()
engine = Engine(config=config)

# The engine natively slices semicolon-delimited blocks into independent AST nodes
sql_payload = "SELECT * FROM users WHERE id = '%s';"
results = engine.analyze_string(sql_payload, dialect="postgresql")

for issue in results.issues:
    print(f"[{issue.severity.name}] {issue.rule_id}: {issue.message}")
```

## 2. Low-Level Analyzer Hooks

To bypass the `Engine` parallelization overhead entirely (e.g., executing validations inside a synchronous web request handler), bypass the `Engine` abstraction and securely manage the `Analyzer` queue manually:

```python
from slowql.analyzers.registry import get_analyzers
from slowql.parser.tokenizer import parse_queries

queries = parse_queries("SELECT id FROM t LIMIT 0", dialect="mysql")
analyzers = get_analyzers()

for query in queries:
    for analyzer in analyzers:
        issues = analyzer.analyze(query)
        if issues:
            print(f"Detected explicit rule infractions natively via {analyzer.__class__.__name__}")
```

## 3. Constructing Query Modals

To synthesize mock structures outside of `Tokenizer` arrays seamlessly—such as executing assertions inside `pytest` tracks—construct `Query` elements explicitly:

```python
import sqlglot
from slowql.core.models import Location, Query

raw_sql = "DELETE FROM production.users"
ast = sqlglot.parse_one(raw_sql)

query = Query(
    raw=raw_sql, 
    normalized=raw_sql, 
    dialect="snowflake", 
    location=Location(line=1, column=1), 
    query_type="DELETE", 
    ast=ast
)
```

## 4. Programmatic Serialization

SlowQL internally delegates all log outputs to `BaseReporter` interfaces. Directly initialize `JsonReporter` or `SarifReporter` models to capture the absolute `AnalysisResult` dump into string memory without touching physical disks.

```python
from slowql.reporters.sarif_reporter import SarifReporter

result = engine.analyze_file("dangerous_migrations.sql")
reporter = SarifReporter()

# Serializes the entire payload into strict SARIF standards dynamically
json_payload_string = reporter.format(result)

# Send the payload via requests to your telemetry servers internally
# requests.post(TELEMETRY_ENDPOINT, json=json_payload_string)
```
