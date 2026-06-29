# Inline Suppression

Rules can be silenced using directives written in SQL comments. No configuration file changes required.

## Directives

### Current Line

```sql
SELECT * FROM archive;  -- slowql-disable-line PERF-SCAN-001
```

### Next Line

``` SQL
-- slowql-disable-next-line SEC-INJ-001
SELECT id FROM sessions WHERE id = $1;
```

### Block

``` SQL
-- slowql-disable PERF-SCAN-001
SELECT * FROM event_stream;
SELECT * FROM session_log;
-- slowql-enable PERF-SCAN-001
```
Block without matching `enable` extends to end of file.

### Entire File

``` SQL
-- slowql-disable-file PERF-SCAN-001
```
Can appear anywhere in the file.

## Rule ID Formats

All directives accept:

**Exact rule ID**:

``` SQL
SELECT * FROM t;  -- slowql-disable-line PERF-SCAN-001
```

**Prefix (suppresses all matching rules)**:
``` SQL
SELECT * FROM t;  -- slowql-disable-line PERF-SCAN
```

**Comma-separated**:
``` SQL
SELECT * FROM t;  -- slowql-disable-line PERF-SCAN-001, SEC-INJ-001
```

**No rule ID (suppresses all rules)**:
``` SQL
SELECT * FROM t;  -- slowql-disable-line
```
Matching is case-insensitive.

## In Application Code
Suppression works in Python, TypeScript, Go, Ruby, and other extracted languages:

``` Python
query = "SELECT * FROM archive"  # slowql-disable-line PERF-SCAN-001
```

``` TypeScript
const q = "DELETE FROM temp_data";  // slowql-disable-line REL-DATA-001
```

## Reporting
Suppressed issues are counted separately and reported at the end of output:
``` text
  (12 issues suppressed by inline directives)
```

## When to Use
Use suppression for:

- Intentional full table scans in maintenance scripts
- Known acceptable patterns in generated SQL
- Intentional destructive operations in cleanup scripts

For permanent project-wide exceptions, use `disabled_rules` in your config file instead.