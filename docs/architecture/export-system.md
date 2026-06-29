# Export System

SlowQL supports multiple output formats and file export options.

## Output Formats

### Console (default)

Human-readable output with color-coded severity, code snippets, and documentation links.

```bash
slowql src/
```

### JSON
Machine-readable output. Useful for custom tooling and pipelines.
``` Bash
slowql src/ --format json
```

JSON Structure:
``` JSON
{
  "issues": [...],
  "statistics": {
    "total_queries": 142,
    "total_issues": 3,
    "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
    "by_dimension": {"security": 2, "performance": 1, ...},
    "analysis_time_ms": 287.4,
    "parse_time_ms": 45.2
  },
  "dialect": "postgresql",
  "version": "2.0.0",
  "timestamp": "2025-06-27T15:00:00Z",
  "suppressed_count": 12
}
```

### SARIF
Static Analysis Results Interchange Format (SARIF 2.1.0). Integrates with GitHub Code Scanning.
``` Bash
slowql src/ --format sarif
```

### Github Actions
Native GitHub Actions annotation format. Places error annotations directly on PR diffs.
``` Bash
slowql src/ --format github-actions
```

## File Exports
Use `--export` to write results to disk while still printing console output:
``` Bash
# Single format
slowql src/ --export json --out reports/

# Multiple formats
slowql src/ --export json --export html --export csv --export sarif --out reports/
```
Files are written to `--out` directory (default: `reports/`):

``` text
reports/
  ├── slowql_report.json
  ├── slowql_report.html
  ├── slowql_report.csv
  └── slowql_report.sarif
```

## JSON Output Design
The `queries` array is deliberately excluded from JSON output. On large repos, including all parsed queries produces files 100MB+ in size and dominates wall time. The statistics object provides aggregate query counts without the full payload.

If you need per-query data, use `--verbose` with console output.
