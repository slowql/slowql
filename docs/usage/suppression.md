# Inline Suppression

SlowQL supports inline suppression directives written as SQL line comments. These directives instruct the engine to skip specific rules for a given line, block, or file without modifying your analysis configuration.

Suppression directives are the standard escape hatch available in every production-grade linter. They exist for cases where a rule fires correctly by design but is not applicable to a specific context, such as an intentional full table scan inside a data migration or a known false positive in generated SQL.

---

## Directives

### Suppress the current line

```sql
SELECT * FROM archive_audit_log;  -- slowql-disable-line PERF-SCAN-001
```

The directive must appear on the same line as the statement it suppresses. Only the specified rule is skipped; all other rules continue to fire on that line.

---

### Suppress the next line

```sql
-- slowql-disable-next-line SEC-INJ-001
SELECT id, password_hash FROM users WHERE id = $1;
```

The directive must appear on the line immediately before the target statement. Blank lines between the directive and the target are allowed; the engine skips them and applies suppression to the next non-blank, non-comment line.

---

### Suppress a block

```sql
-- slowql-disable PERF-SCAN-001
SELECT * FROM event_stream;
SELECT * FROM session_log;
-- slowql-enable PERF-SCAN-001
```

All lines between the `disable` and `enable` directives are suppressed for the named rule. If no matching `enable` is present, suppression applies to the remainder of the file.

---

### Suppress the entire file

```sql
-- slowql-disable-file PERF-SCAN-001
```

This directive can appear anywhere in the file. It suppresses the named rule for every issue found in that file, regardless of line number.

---

## Rule ID formats

All four directives accept the following formats for the rule identifier:

**Exact rule ID.** Only the specified rule is suppressed.

```sql
SELECT * FROM t;  -- slowql-disable-line PERF-SCAN-001
```

**Prefix.** All rules whose ID starts with the prefix are suppressed.

```sql
SELECT * FROM t;  -- slowql-disable-line PERF-SCAN
```

The prefix `PERF-SCAN` would suppress `PERF-SCAN-001`, `PERF-SCAN-002`, and any other rule in that group.

**Multiple rule IDs.** Comma-separated values are supported on a single directive.

```sql
SELECT * FROM t;  -- slowql-disable-line PERF-SCAN-001, SEC-INJ-001
```

**No rule ID.** Omitting the rule ID suppresses all rules for that scope.

```sql
SELECT * FROM t;  -- slowql-disable-line
```

Matching is case-insensitive. `perf-scan-001` and `PERF-SCAN-001` are equivalent.

---

## Suppression inside string literals

Directives inside SQL string literals are ignored. The following does not suppress anything:

```sql
SELECT '-- slowql-disable-line PERF-SCAN-001' AS note FROM t;
```

---

## Reporting

Suppressed issues are not included in the reported output or counted toward severity thresholds. The engine tracks how many issues were suppressed per run and exposes that count via the Python API in `AnalysisResult.suppressed_count`.

---

## When to use suppression

Suppression should be the last resort, applied only when a rule fires correctly but is contextually inapplicable. Common legitimate uses:

- Intentional full table scans inside maintenance scripts or backfill jobs.
- Known false positives in generated SQL that cannot be refactored.
- Schema migration files where destructive operations are expected.

For persistent patterns, prefer `disabled_rules` in your configuration file, which disables a rule globally across all files.
