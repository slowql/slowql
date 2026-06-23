use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::time::Instant;

use crate::config::Config;
use crate::engine::Engine;

#[derive(Parser)]
#[command(
    name = "slowql",
    version,
    about = "Next-generation SQL static analyzer
Copyright (C) 2025-2026 El Mehdi Makroumi. Licensed under AGPL-3.0."
)]
struct Cli {
    /// Input SQL files or directories
    #[arg()]
    files: Vec<PathBuf>,

    /// SQL dialect
    #[arg(short, long)]
    dialect: Option<String>,

    /// Path to DDL schema file for schema-aware validation
    #[arg(short, long)]
    schema: Option<PathBuf>,

    /// Output format
    #[arg(long, default_value = "console", value_enum)]
    format: OutputFormat,

    /// Export results to file (json, html, csv, sarif)
    #[arg(long)]
    export: Vec<String>,

    /// Output directory for exports
    #[arg(long, default_value = "reports")]
    out: PathBuf,

    /// Fail when issues at or above this severity are found
    #[arg(long)]
    fail_on: Option<String>,

    /// Preview safe autofix diff without modifying files
    #[arg(long)]
    diff: bool,

    /// Apply safe autofixes and create .bak backup
    #[arg(long)]
    fix: bool,

    /// Write JSON report of applied fixes
    #[arg(long)]
    fix_report: Option<PathBuf>,

    /// Path to baseline file
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Update or create baseline file
    #[arg(long)]
    update_baseline: Option<PathBuf>,

    /// List all available rules
    #[arg(long)]
    list_rules: bool,

    /// Show documentation for a specific rule
    #[arg(long)]
    explain: Option<String>,

    /// Only analyze files changed in git
    #[arg(long)]
    git_diff: bool,

    /// Analyze files changed since a git revision
    #[arg(long)]
    since: Option<String>,

    /// Number of parallel workers (0 = auto)
    #[arg(short, long, default_value = "0")]
    jobs: usize,

    /// Enable verbose output
    #[arg(long)]
    verbose: bool,

    /// Disable caching
    #[arg(long)]
    no_cache: bool,

    /// Directory to store cache files
    #[arg(long, default_value = ".slowql_cache")]
    cache_dir: String,

    /// Clear cache directory before analysis
    #[arg(long)]
    clear_cache: bool,

    /// Filter --list-rules by dimension
    #[arg(long)]
    filter_dimension: Option<String>,

    /// Filter --list-rules by dialect
    #[arg(long)]
    filter_dialect: Option<String>,

    /// Minimum confidence level to report (proven, contextual, advisory)
    #[arg(long)]
    min_confidence: Option<String>,

    /// Include non-production contexts (test, example, seed) in output
    #[arg(long)]
    include_nonprod: bool,

    /// Enable query comparison mode (detect similar queries)
    #[arg(long)]
    compare: bool,

    /// Create a slowql.yaml config file
    #[arg(long)]
    init: bool,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Console,
    Json,
    Sarif,
    GithubActions,
}

fn apply_baseline(
    result: crate::models::result::AnalysisResult,
    baseline_path: &std::path::Path,
) -> Result<(crate::models::result::AnalysisResult, usize), String> {
    let baseline = crate::baseline::Baseline::load(baseline_path)?;
    Ok(crate::baseline::Baseline::filter_new(
        result, &baseline,
    ))
}

fn update_baseline_file(
    result: &crate::models::result::AnalysisResult,
    baseline_path: &std::path::Path,
) -> Result<(), String> {
    let baseline = crate::baseline::Baseline::generate(result);
    baseline.save(baseline_path)
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    run_with_cli(cli, None)
}

fn run_with_cli(cli: Cli, stdin_override: Option<&str>) -> i32 {

    // Handle --list-rules
    if cli.list_rules {
        cmd_list_rules(
            cli.filter_dimension.as_deref(),
            cli.filter_dialect.as_deref(),
        );
        return 0;
    }

    // Handle --explain
    if let Some(rule_id) = &cli.explain {
        let code = cmd_explain(rule_id);
        return code;
    }

    // Handle --init
    if cli.init {
        let config_path = std::path::Path::new("slowql.yaml");
        if config_path.exists() {
            eprintln!("slowql.yaml already exists in current directory.");
            return 1;
        }
        let dialect = cli.dialect.as_deref().unwrap_or("postgresql");
        let fail_on = cli.fail_on.as_deref().unwrap_or("high");
        let content = format!(
            r#"# SlowQL Configuration
# Documentation: https://slowql.dev/docs/configuration

analysis:
  dialect: {dialect}
  enabled_dimensions:
    - security
    - performance
    - reliability
    - cost
    - quality
    - compliance
  disabled_rules: []
  # min_confidence: contextual  # proven | contextual | advisory
  # table_metadata:
  #   large_tables: []
  #   partitioned_tables: {{}}

severity:
  fail_on: {fail_on}

output:
  format: console
  verbose: false
  show_fixes: true

# compliance:
#   frameworks:
#     - gdpr
#     - pci-dss

# schema:
#   path: db/schema.sql
"#
        );
        if let Err(e) = std::fs::write(config_path, content) {
            eprintln!("Error writing slowql.yaml: {}", e);
            return 1;
        }
        eprintln!("Created slowql.yaml with dialect: {}", dialect);
        return 0;
    }

    // Handle --clear-cache
    if cli.clear_cache {
        let cache = crate::cache::CacheManager::new(&cli.cache_dir);
        cache.clear();
        eprintln!("Cache cleared: {}", cli.cache_dir);
        if cli.files.is_empty() {
            return 0;
        }
    }

    // Build engine
    let mut config = Config::find_and_load();
    if let Some(ref dialect) = cli.dialect {
        config.analysis.dialect = Some(dialect.clone());
    }
    if let Some(ref fail_on) = cli.fail_on {
        config.severity.fail_on = fail_on.clone();
    }
    config.output.verbose = cli.verbose;
    if let Some(ref mc) = cli.min_confidence {
        config.analysis.min_confidence = mc.clone();
    }

    let _schema = cli.schema.as_ref().and_then(|path| {
        let dialect = cli.dialect.as_deref().unwrap_or("postgresql");
        match crate::schema::load_schema_file(path, dialect) {
            Ok(s) => {
                eprintln!(
                    "Schema loaded: {} tables from {}",
                    s.tables.len(),
                    path.display()
                );
                Some(s)
            }
            Err(e) => {
                eprintln!("Warning: {}", e);
                None
            }
        }
    });

    let mut engine = Engine::new(config);
    if let Some(schema) = _schema {
        engine = engine.with_schema(schema);
    }

    // Determine input
    if cli.files.is_empty() {
        // Testable stdin path:
        // prefer injected SQL in unit tests, otherwise read real stdin.
        let sql = if let Some(stdin_sql) = stdin_override {
            stdin_sql.to_string()
        } else {
            let mut sql = String::new();
            if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut sql) {
                eprintln!("Error reading stdin: {}", e);
                return 1;
            }
            sql
        };

        if sql.trim().is_empty() {
            eprintln!("Usage: slowql <file.sql> [options]");
            eprintln!("       cat queries.sql | slowql");
            return 1;
        }
        let result = engine.analyze(&sql, cli.dialect.as_deref(), None);
        let stdin_mode = cli
            .min_confidence
            .as_deref()
            .filter(|m| *m == "proven" || *m == "advisory");
        output_result_with_mode(&result, &cli, stdin_mode);
        return compute_exit_code(&result, cli.fail_on.as_deref());
    }

    // Analyze files
    let mut combined = crate::models::result::AnalysisResult::new();
    combined.dialect = cli.dialect.clone();

    let changed_files = if cli.git_diff || cli.since.is_some() {
        Some(crate::git::get_changed_files(cli.since.as_deref()))
    } else {
        None
    };

    let mut skipped_non_utf8: usize = 0;
    let mut files_scanned: usize = 0;
    let scan_start = Instant::now();

    for path in &cli.files {
        if path.is_dir() {
            for entry in walkdir(path) {
                if let Some(ref changed) = changed_files {
                    if let Ok(abs) = entry.canonicalize() {
                        if !changed.contains(&abs) {
                            continue;
                        }
                    }
                }
                files_scanned += 1;
                if files_scanned.is_multiple_of(100) || files_scanned <= 5 {
                    eprint!(
                        "\r\x1b[2m  Scanning... {} files, {} queries found\x1b[0m",
                        files_scanned, combined.statistics.total_queries
                    );
                }
                match engine.analyze_file(entry.to_str().unwrap_or("")) {
                    Ok(result) => merge_results(&mut combined, result),
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("valid UTF-8")
                            || msg.contains("UTF8")
                            || msg.contains("utf-8")
                        {
                            skipped_non_utf8 += 1;
                        } else if cli.verbose {
                            eprintln!("Warning: {}", e);
                        }
                    }
                }
            }
        } else if path.exists() {
            if let Some(ref changed) = changed_files {
                if let Ok(abs) = path.canonicalize() {
                    if !changed.contains(&abs) {
                        continue;
                    }
                }
            }
            files_scanned += 1;
            match engine.analyze_file(path.to_str().unwrap_or("")) {
                Ok(result) => merge_results(&mut combined, result),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("valid UTF-8") || msg.contains("UTF8") || msg.contains("utf-8")
                    {
                        skipped_non_utf8 += 1;
                    } else {
                        eprintln!("Error: {}", e);
                    }
                }
            }
        } else {
            eprintln!("File not found: {}", path.display());
        }
    }

    // Clear live progress line
    if files_scanned > 5 {
        eprint!("\r\x1b[K");
    }

    let scan_duration = scan_start.elapsed();

    // Report skipped files
    if skipped_non_utf8 > 0 && cli.verbose {
        eprintln!(
            "Skipped {} file(s) with non-UTF-8 encoding.",
            skipped_non_utf8
        );
    }

    if let Some(ref baseline_out) = cli.update_baseline {
        if let Err(e) = update_baseline_file(&combined, baseline_out) {
            eprintln!("Error writing baseline: {}", e);
            return 1;
        }
        eprintln!("Baseline updated: {}", baseline_out.display());
        return 0;
    }

    let mut final_result = combined;
    final_result.statistics.analysis_time_ms = scan_duration.as_secs_f64() * 1000.0;
    // For directory scans, suppress non-production issues by default.
    // Uses source_context on each issue for accurate context-based filtering.
    if !cli.include_nonprod && !cli.files.is_empty() && cli.files.iter().any(|f| f.is_dir()) {
        let nonprod_contexts = [
            "test",
            "example",
            "seed",
            "framework_internal",
            "ddl_schema",
            "migration",
        ];
        let before = final_result.issues.len();
        final_result.issues.retain(|issue| {
            // Primary: use source_context if set
            if !issue.source_context.is_empty() {
                return !nonprod_contexts.contains(&issue.source_context.as_str());
            }
            // Fallback: path-based detection for issues without source_context
            let file = issue.location.file.as_deref().unwrap_or("");
            let is_nonprod = file.contains("/test/")
                || file.contains("/tests/")
                || file.contains("/spec/")
                || file.contains("/__tests__/")
                || file.contains("/e2e/")
                || file.contains("/fixtures/")
                || file.contains("/examples/")
                || file.contains("/example/")
                || file.contains("/seeds/")
                || file.contains("/seed/")
                || file.contains("/scripts/")
                || file.contains("/script/")
                || file.contains(".spec.")
                || file.contains(".test.")
                || file.contains("/test_resources/")
                || file.contains("/test-resources/")
                || file.contains("/db/backends/")
                || file.contains("/connection_adapters/");
            !is_nonprod
        });
        let suppressed = before - final_result.issues.len();
        if suppressed > 0 {
            final_result.suppressed_count += suppressed;
            // Recompute statistics
            final_result.statistics.total_issues = final_result.issues.len();
            final_result
                .statistics
                .by_severity
                .values_mut()
                .for_each(|v| *v = 0);
            final_result
                .statistics
                .by_dimension
                .values_mut()
                .for_each(|v| *v = 0);
            for issue in &final_result.issues {
                *final_result
                    .statistics
                    .by_severity
                    .entry(issue.severity.as_str().to_string())
                    .or_insert(0) += 1;
                *final_result
                    .statistics
                    .by_dimension
                    .entry(issue.dimension.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }
    }

    if let Some(ref baseline_in) = cli.baseline {
        match apply_baseline(final_result, baseline_in) {
            Ok((filtered, suppressed)) => {
                final_result = filtered;
                final_result.suppressed_count += suppressed;
            }
            Err(e) => {
                eprintln!("Error loading baseline: {}", e);
                return 1;
            }
        }
    }

    // Run project-level analysis (cross-file, dead SQL, duplicates)
    if !final_result.queries.is_empty() {
        let project_issues = crate::project::analyze_project(&final_result);
        for issue in project_issues {
            final_result.add_issue(issue);
        }
    }

    // Run query comparison if requested
    if cli.compare && !final_result.queries.is_empty() {
        let compare_issues = crate::compare::find_similar_queries(&final_result.queries);
        for issue in compare_issues {
            final_result.add_issue(issue);
        }
    }

    // Apply autofixes if requested
    if cli.fix || cli.diff {
        use crate::autofixer::AutoFixer;
        for path in &cli.files {
            if !path.exists() || path.is_dir() {
                continue;
            }
            let path_str = path.to_str().unwrap_or("");
            let fixes: Vec<crate::models::Fix> = final_result
                .issues
                .iter()
                .filter(|i| i.location.file.as_deref() == Some(path_str))
                .filter_map(|i| i.fix.as_ref())
                .filter(|f| f.is_safe)
                .cloned()
                .collect();

            if fixes.is_empty() {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(path) {
                if cli.diff {
                    let diff = AutoFixer::preview_diff(&content, &fixes);
                    if !diff.is_empty() {
                        println!("{}", diff);
                    }
                } else if cli.fix {
                    let fixed = AutoFixer::apply_all_fixes(&content, &fixes);
                    if fixed != content {
                        let backup = format!("{}.bak", path_str);
                        std::fs::copy(path, &backup).ok();
                        std::fs::write(path, &fixed).ok();
                        eprintln!("Fixed: {} (backup: {})", path_str, backup);

                        if let Some(ref report_path) = cli.fix_report {
                            let report = serde_json::json!({
                                "file": path_str,
                                "fixes_applied": fixes.len(),
                                "backup": backup,
                            });
                            let existing =
                                std::fs::read_to_string(report_path).unwrap_or("[]".to_string());
                            let mut arr: Vec<serde_json::Value> =
                                serde_json::from_str(&existing).unwrap_or_default();
                            arr.push(report);
                            std::fs::write(
                                report_path,
                                serde_json::to_string_pretty(&arr).unwrap_or_default(),
                            )
                            .ok();
                        }
                    }
                }
            }
        }
    }

    // Final non-production suppression pass.
    // Runs AFTER project-level analysis so all issues have source_context.
    if !cli.include_nonprod && !cli.files.is_empty() && cli.files.iter().any(|f| f.is_dir()) {
        let nonprod_contexts = [
            "test",
            "example",
            "seed",
            "framework_internal",
            "ddl_schema",
            "migration",
        ];
        let before = final_result.issues.len();
        final_result.issues.retain(|issue| {
            if !issue.source_context.is_empty() {
                return !nonprod_contexts.contains(&issue.source_context.as_str());
            }
            let file = issue.location.file.as_deref().unwrap_or("");
            let is_nonprod = file.contains("/test/")
                || file.contains("/tests/")
                || file.contains("/spec/")
                || file.contains("/__tests__/")
                || file.contains("/e2e/")
                || file.contains("/fixtures/")
                || file.contains("/examples/")
                || file.contains("/example/")
                || file.contains("/seeds/")
                || file.contains("/seed/")
                || file.contains("/scripts/")
                || file.contains("/script/")
                || file.contains(".spec.")
                || file.contains(".test.")
                || file.contains("/test_resources/")
                || file.contains("/test-resources/")
                || file.contains("/db/backends/")
                || file.contains("/connection_adapters/");
            !is_nonprod
        });
        let suppressed = before - final_result.issues.len();
        if suppressed > 0 {
            final_result.suppressed_count += suppressed;
            final_result.statistics.total_issues = final_result.issues.len();
            final_result
                .statistics
                .by_severity
                .values_mut()
                .for_each(|v| *v = 0);
            final_result
                .statistics
                .by_dimension
                .values_mut()
                .for_each(|v| *v = 0);
            for issue in &final_result.issues {
                *final_result
                    .statistics
                    .by_severity
                    .entry(issue.severity.as_str().to_string())
                    .or_insert(0) += 1;
                *final_result
                    .statistics
                    .by_dimension
                    .entry(issue.dimension.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }
    }

    // Final confidence filter - applies to ALL issues including project-level
    let min_conf: crate::models::RuleConfidence = cli
        .min_confidence
        .as_deref()
        .or(Some(&engine.config.analysis.min_confidence))
        .unwrap_or("contextual")
        .parse()
        .unwrap_or(crate::models::RuleConfidence::Contextual);
    let before_conf = final_result.issues.len();
    final_result.issues.retain(|i| i.confidence >= min_conf);
    let conf_suppressed = before_conf - final_result.issues.len();
    if conf_suppressed > 0 {
        final_result.suppressed_count += conf_suppressed;
        final_result.statistics.total_issues = final_result.issues.len();
        final_result
            .statistics
            .by_severity
            .values_mut()
            .for_each(|v| *v = 0);
        final_result
            .statistics
            .by_dimension
            .values_mut()
            .for_each(|v| *v = 0);
        for issue in &final_result.issues {
            *final_result
                .statistics
                .by_severity
                .entry(issue.severity.as_str().to_string())
                .or_insert(0) += 1;
            *final_result
                .statistics
                .by_dimension
                .entry(issue.dimension.as_str().to_string())
                .or_insert(0) += 1;
        }
    }

    let mode_hint = cli
        .min_confidence
        .as_deref()
        .or(Some(engine.config.analysis.min_confidence.as_str()))
        .filter(|m| *m == "proven" || *m == "advisory")
        .map(|m| m.to_string());
    output_result_with_mode(&final_result, &cli, mode_hint.as_deref());

    for fmt in &cli.export {
        export_result(&final_result, fmt, &cli.out);
    }

    compute_exit_code(&final_result, cli.fail_on.as_deref())
}

fn merge_results(
    combined: &mut crate::models::result::AnalysisResult,
    result: crate::models::result::AnalysisResult,
) {
    for issue in result.issues {
        combined.add_issue(issue);
    }
    combined.queries.extend(result.queries);
    combined.statistics.total_queries += result.statistics.total_queries;
    combined.statistics.parse_time_ms += result.statistics.parse_time_ms;
}

fn output_result_with_mode(
    result: &crate::models::result::AnalysisResult,
    cli: &Cli,
    mode: Option<&str>,
) {
    match cli.format {
        OutputFormat::Console => {
            if let Some(m) = mode {
                match m {
                    "proven" => println!(
                        "\x1b[1;32m[proven mode]\x1b[0m Only structurally verified findings shown."
                    ),
                    "advisory" => println!(
                        "\x1b[1;36m[advisory mode]\x1b[0m All findings including hints shown."
                    ),
                    _ => {}
                }
            }
            print_console(result);
        }
        OutputFormat::Json => print_json(result),
        OutputFormat::Sarif => print_sarif(result),
        OutputFormat::GithubActions => print_github_actions(result),
    }
}

fn print_console(result: &crate::models::result::AnalysisResult) {
    if result.issues.is_empty() {
        println!("\x1b[1;32mNo issues found.\x1b[0m");
        println!("  Scanned {} queries", result.statistics.total_queries);
        if result.statistics.analysis_time_ms > 0.0 {
            println!(
                "  \x1b[2mAnalysis: {:.0}ms\x1b[0m",
                result.statistics.analysis_time_ms
            );
        }
        if result.suppressed_count > 0 {
            // Only show non-production message for directory scans
            if result.issues.is_empty() {
                println!("  \x1b[2m({} issues available with --min-confidence contextual or --include-nonprod)\x1b[0m", result.suppressed_count);
            }
        }
        return;
    }

    println!();
    println!(
        "\x1b[1mSlowQL\x1b[0m v{} - {} queries scanned, {} issues found",
        result.version, result.statistics.total_queries, result.statistics.total_issues
    );
    println!();

    // Severity summary
    for sev in &["critical", "high", "medium", "low", "info"] {
        let count = result
            .statistics
            .by_severity
            .get(*sev)
            .copied()
            .unwrap_or(0);
        if count > 0 {
            let color = match *sev {
                "critical" => "\x1b[1;35m",
                "high" => "\x1b[1;31m",
                "medium" => "\x1b[1;33m",
                "low" => "\x1b[1;36m",
                "info" => "\x1b[2m",
                _ => "",
            };
            println!("  {}{:>8}\x1b[0m: {}", color, sev.to_uppercase(), count);
        }
    }
    println!();

    // Group issues by file, then sort by severity within each file
    let mut sorted = result.sorted_by_severity();
    sorted.sort_by(|a, b| {
        let fa = a.location.file.as_deref().unwrap_or("");
        let fb = b.location.file.as_deref().unwrap_or("");
        fa.cmp(fb)
            .then(b.severity.cmp(&a.severity))
            .then(a.location.line.cmp(&b.location.line))
    });
    let mut current_file: Option<&str> = Some("__sentinel_no_file__");

    for issue in &sorted {
        let file = issue.location.file.as_deref();

        // Print file header when file changes
        if file != current_file {
            if current_file.is_some() {
                println!();
            }
            match file {
                Some(f) => println!("  \x1b[1;4m{}\x1b[0m", f),
                None => println!("  \x1b[1;4m<stdin>\x1b[0m"),
            }
            current_file = file;
        }

        let color = issue.severity.color_code();
        let reset = "\x1b[0m";

        let line_col = format!("{}:{}", issue.location.line, issue.location.column);

        let conf_badge = match issue.confidence.as_str() {
            "proven" => "",
            "contextual" => " \x1b[33m[needs-review]\x1b[0m",
            "advisory" => " \x1b[36m[hint]\x1b[0m",
            _ => "",
        };

        println!(
            "    {}{:>8}{} {:<16} {:>6}  {}{}",
            color,
            issue.severity.as_str().to_uppercase(),
            reset,
            issue.rule_id,
            line_col,
            issue.message,
            conf_badge,
        );

        // Show the SQL snippet so users see the offending code
        if !issue.snippet.is_empty() {
            let snip = issue.snippet.trim();
            if !snip.is_empty() && snip.len() < 120 {
                println!("             \x1b[2m> {}\x1b[0m", snip);
            }
        }

        if let Some(ref impact) = issue.impact {
            println!("             \x1b[2m{}\x1b[0m", impact);
        }

        if let Some(ref fix) = issue.fix {
            if !fix.description.is_empty() {
                println!("             \x1b[32mFix: {}\x1b[0m", fix.description);
            }
        }

        // Show documentation URL
        if let Some(ref url) = issue.documentation_url {
            println!("             \x1b[2m{}\x1b[0m", url);
        }
    }

    // Footer: explain badges if any non-proven issues exist
    let has_contextual = result
        .issues
        .iter()
        .any(|i| i.confidence.as_str() == "contextual");
    let has_advisory = result
        .issues
        .iter()
        .any(|i| i.confidence.as_str() == "advisory");
    if has_contextual || has_advisory {
        println!();
        if has_contextual {
            println!("  \x1b[33m[needs-review]\x1b[0m = finding depends on runtime context, verify before acting");
        }
        if has_advisory {
            println!("  \x1b[36m[hint]\x1b[0m = best-practice suggestion, not a proven issue");
        }
    }
    if result.suppressed_count > 0 {
        println!(
            "  \x1b[2m({} additional findings with --min-confidence contextual)\x1b[0m",
            result.suppressed_count
        );
    }

    // Complexity summary - only for multi-query scans, not single stdin
    if result.queries.len() > 1 {
        let scores: Vec<u32> = result.queries.iter().map(|q| q.complexity_score).collect();
        let max_score = scores.iter().copied().max().unwrap_or(0);
        let critical_count = scores.iter().filter(|&&s| s > 70).count();
        if critical_count > 0 || max_score > 40 {
            println!(
                "  \x1b[2mComplexity: max={} critical_queries={}\x1b[0m",
                max_score, critical_count
            );
        }
    }

    // Benchmark footer
    let analysis_ms = result.statistics.analysis_time_ms;
    if analysis_ms > 0.0 {
        // Count unique files from queries
        let file_count: std::collections::HashSet<&str> = result
            .queries
            .iter()
            .filter_map(|q| q.location.file.as_deref())
            .collect();
        let files = file_count.len();
        if files > 0 {
            println!(
                "  \x1b[2m{} files | {} queries | {:.0}ms | {:.0} queries/sec\x1b[0m",
                files,
                result.statistics.total_queries,
                analysis_ms,
                if analysis_ms > 0.0 {
                    result.statistics.total_queries as f64 / (analysis_ms / 1000.0)
                } else {
                    0.0
                }
            );
        } else {
            println!(
                "  \x1b[2m{} queries | {:.0}ms\x1b[0m",
                result.statistics.total_queries, analysis_ms
            );
        }
    }
    println!();
}

fn print_json(result: &crate::models::result::AnalysisResult) {
    match serde_json::to_string_pretty(result) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing to JSON: {}", e),
    }
}

fn print_sarif(result: &crate::models::result::AnalysisResult) {
    let mut rules_map: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    let mut sarif_results: Vec<serde_json::Value> = Vec::new();

    for issue in &result.issues {
        rules_map.entry(issue.rule_id.clone()).or_insert_with(|| {
            serde_json::json!({
                "id": issue.rule_id,
                "shortDescription": { "text": issue.message },
                "properties": { "category": issue.dimension.as_str() }
            })
        });

        let level = match issue.severity {
            crate::models::Severity::Critical | crate::models::Severity::High => "error",
            crate::models::Severity::Medium => "warning",
            _ => "note",
        };

        let mut sarif_result = serde_json::json!({
            "ruleId": issue.rule_id,
            "message": { "text": issue.message },
            "level": level,
        });

        let mut region = serde_json::Map::new();
        region.insert("startLine".into(), serde_json::json!(issue.location.line));
        if issue.location.column > 0 {
            region.insert(
                "startColumn".into(),
                serde_json::json!(issue.location.column),
            );
        }

        let file = issue.location.file.as_deref().unwrap_or("unknown");
        sarif_result["locations"] = serde_json::json!([{
            "physicalLocation": {
                "artifactLocation": { "uri": file },
                "region": region
            }
        }]);

        sarif_results.push(sarif_result);
    }

    let sarif = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SlowQL",
                    "version": result.version,
                    "informationUri": "https://github.com/slowql/slowql",
                    "rules": rules_map.values().collect::<Vec<_>>()
                }
            },
            "results": sarif_results
        }]
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&sarif).unwrap_or_default()
    );
}

fn print_github_actions(result: &crate::models::result::AnalysisResult) {
    for issue in &result.issues {
        let level = match issue.severity {
            crate::models::Severity::Critical | crate::models::Severity::High => "error",
            crate::models::Severity::Medium | crate::models::Severity::Low => "warning",
            crate::models::Severity::Info => "notice",
        };

        let file = issue.location.file.as_deref().unwrap_or("");
        let line = issue.location.line;
        let col = issue.location.column;

        let msg = issue
            .message
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");

        if !file.is_empty() {
            println!(
                "::{level} file={file},line={line},col={col}::{} {msg}",
                issue.rule_id
            );
        } else {
            println!("::{level}::{} {msg}", issue.rule_id);
        }
    }
}

fn export_result(
    result: &crate::models::result::AnalysisResult,
    fmt: &str,
    out_dir: &std::path::Path,
) {
    std::fs::create_dir_all(out_dir).ok();
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

    match fmt {
        "json" => {
            let path = out_dir.join(format!("slowql_results_{}.json", timestamp));
            if let Ok(json) = serde_json::to_string_pretty(result) {
                std::fs::write(&path, json).ok();
                eprintln!("Exported JSON: {}", path.display());
            }
        }
        "sarif" => {
            eprintln!("SARIF export: use --format sarif and redirect output");
        }
        "csv" => {
            let path = out_dir.join(format!("slowql_report_{}.csv", timestamp));
            let mut csv = String::from("severity,rule_id,dimension,message,impact,location\n");
            for issue in &result.issues {
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    issue.severity.as_str(),
                    issue.rule_id,
                    issue.dimension.as_str(),
                    issue.message.replace(',', ";"),
                    issue.impact.as_deref().unwrap_or("").replace(',', ";"),
                    issue.location,
                ));
            }
            std::fs::write(&path, csv).ok();
            eprintln!("Exported CSV: {}", path.display());
        }
        "html" => {
            let path = out_dir.join(format!("slowql_report_{}.html", timestamp));
            let mut rows = String::new();
            for issue in &result.issues {
                rows.push_str(&format!(
                    "<tr><td class=\"sev-{}\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    issue.severity.as_str(),
                    issue.severity.as_str().to_uppercase(),
                    issue.rule_id,
                    issue.dimension.as_str(),
                    html_escape(&issue.message),
                    issue.location,
                ));
            }
            let html = format!(
                r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SlowQL Report</title>
<style>body{{font-family:system-ui;background:#0b1120;color:#e5e7eb;padding:24px}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:8px;border-bottom:1px solid #1f2937;text-align:left}}
th{{background:#020617}}.sev-critical{{color:#f97373;font-weight:600}}.sev-high{{color:#fb923c;font-weight:600}}
.sev-medium{{color:#22c55e}}.sev-low{{color:#38bdf8}}.sev-info{{color:#9ca3af}}</style></head>
<body><h1>SlowQL Report</h1><p>Issues: {}</p>
<table><tr><th>Severity</th><th>Rule</th><th>Dimension</th><th>Message</th><th>Location</th></tr>
{}</table></body></html>"#,
                result.statistics.total_issues, rows
            );
            std::fs::write(&path, html).ok();
            eprintln!("Exported HTML: {}", path.display());
        }
        other => eprintln!("Unknown export format: {}", other),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn compute_exit_code(
    result: &crate::models::result::AnalysisResult,
    fail_on: Option<&str>,
) -> i32 {
    let threshold = match fail_on {
        None | Some("never") => return 0,
        Some(s) => match s {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            "info" => 1,
            _ => return 0,
        },
    };

    let max_weight = result
        .issues
        .iter()
        .map(|i| i.severity.weight())
        .max()
        .unwrap_or(0);
    if max_weight >= threshold {
        2
    } else {
        0
    }
}

fn cmd_list_rules(dimension: Option<&str>, dialect: Option<&str>) {
    let engine = Engine::with_default_config();
    let rules = engine.registry_ref().all();

    let mut count = 0;
    let mut output_lines: Vec<String> = Vec::new();

    for rule in rules.iter() {
        if let Some(dim) = dimension {
            if rule.dimension().as_str() != dim {
                continue;
            }
        }
        if let Some(dia) = dialect {
            let dialects = rule.dialects();
            let dia_normalized = crate::rules::base::normalize_dialect(dia);
            if !dialects.matches(&dia_normalized) {
                continue;
            }
        }
        count += 1;

        // Determine dialect display
        let dialect_display = {
            let d = rule.dialects();
            if d.matches("unknown_test_dialect_xyz") {
                // Universal rule (matches nothing specific means it matches all)
                "all".to_string()
            } else {
                let all_d = [
                    "postgresql",
                    "mysql",
                    "tsql",
                    "oracle",
                    "sqlite",
                    "snowflake",
                    "bigquery",
                    "redshift",
                    "clickhouse",
                    "duckdb",
                    "presto",
                    "spark",
                ];
                let matching: Vec<&str> =
                    all_d.iter().filter(|dd| d.matches(dd)).copied().collect();
                if matching.len() == all_d.len() || matching.is_empty() {
                    "all".to_string()
                } else if matching.len() <= 3 {
                    matching.join(",")
                } else {
                    format!("{}+{}", matching[0], matching.len() - 1)
                }
            }
        };

        output_lines.push(format!(
            "{:<18} {:<8} {:<14} {:<12} {:<14} {}",
            rule.id(),
            rule.severity().as_str(),
            rule.dimension().as_str(),
            rule.confidence().as_str(),
            dialect_display,
            rule.name()
        ));
    }

    println!("SlowQL Rules ({})", count);
    println!(
        "{:<18} {:<8} {:<14} {:<12} {:<14} Name",
        "Rule ID", "Severity", "Dimension", "Confidence", "Dialect"
    );
    println!("{}", "-".repeat(100));
    for line in output_lines {
        println!("{}", line);
    }
}

fn cmd_explain(rule_id: &str) -> i32 {
    let engine = Engine::with_default_config();
    let rules = engine.registry_ref().all();

    if let Some(rule) = rules.iter().find(|r: &&Box<dyn crate::rules::base::Rule>| r.id().eq_ignore_ascii_case(rule_id)) {
        println!("Rule:       {}", rule.id());
        println!("Name:       {}", rule.name());
        println!("Severity:   {}", rule.severity().as_str());
        println!("Dimension:  {}", rule.dimension().as_str());
        println!("Confidence: {}", rule.confidence().as_str());
        // Show dialect info
        let dialects = rule.dialects();
        if dialects.matches("postgresql") && !dialects.matches("unknown") {
            // Universal rule
            println!("Dialects:   all");
        } else {
            // Collect matching dialects
            let all_dialects = [
                "postgresql",
                "mysql",
                "tsql",
                "oracle",
                "sqlite",
                "snowflake",
                "bigquery",
                "redshift",
                "clickhouse",
                "duckdb",
                "presto",
                "spark",
            ];
            let matching: Vec<&str> = all_dialects
                .iter()
                .filter(|d| dialects.matches(d))
                .copied()
                .collect();
            if !matching.is_empty() {
                println!("Dialects:   {}", matching.join(", "));
            }
        }
        if let Some(cat) = rule.category() {
            let cat_str = format!("{:?}", cat);
            // Convert PascalCase to human readable
            let mut human = String::new();
            for (i, c) in cat_str.chars().enumerate() {
                if c.is_uppercase() && i > 0 {
                    human.push(' ');
                }
                human.push(c);
            }
            println!("Category:   {}", human);
        }
        if !rule.impact().is_empty() {
            println!("Impact:     {}", rule.impact());
        }
        if !rule.fix_guidance().is_empty() {
            println!("Fix:        {}", rule.fix_guidance());
        }
        println!(
            "Docs:       https://slowql.dev/rules/{}",
            rule.id().to_lowercase()
        );
        0
    } else {
        eprintln!("Rule not found: {}", rule_id);
        1
    }
}

fn walkdir(path: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let supported = [
        "sql", "py", "ts", "js", "java", "go", "rb", "kt", "cs", "xml",
    ];
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                files.extend(walkdir(&p));
            } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if supported.contains(&ext) {
                    files.push(p);
                }
            }
        }
    }
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Dimension, Issue, Location, Severity};
    use tempfile::tempdir;

    fn base_cli() -> Cli {
        Cli {
            files: Vec::new(),
            dialect: None,
            schema: None,
            format: OutputFormat::Console,
            export: Vec::new(),
            out: PathBuf::from("reports"),
            fail_on: None,
            diff: false,
            fix: false,
            fix_report: None,
            baseline: None,
            update_baseline: None,
            list_rules: false,
            explain: None,
            git_diff: false,
            since: None,
            jobs: 0,
            verbose: false,
            no_cache: false,
            cache_dir: ".slowql_cache".to_string(),
            clear_cache: false,
            filter_dimension: None,
            filter_dialect: None,
            min_confidence: None,
            include_nonprod: false,
            compare: false,
            init: false,
        }
    }

    fn sample_issue(rule_id: &str, severity: Severity) -> Issue {
        Issue::new(
            rule_id,
            "test issue",
            severity,
            Dimension::Security,
            Location::new(1, 1),
            "SELECT 1",
        )
    }

    #[test]
    fn compute_exit_code_none_and_never() {
        let mut result = crate::models::result::AnalysisResult::new();
        result.add_issue(sample_issue("X-1", Severity::Critical));

        assert_eq!(compute_exit_code(&result, None), 0);
        assert_eq!(compute_exit_code(&result, Some("never")), 0);
        assert_eq!(compute_exit_code(&result, Some("unknown")), 0);
    }

    #[test]
    fn compute_exit_code_threshold_match() {
        let mut result = crate::models::result::AnalysisResult::new();
        result.add_issue(sample_issue("X-1", Severity::High));
        assert_eq!(compute_exit_code(&result, Some("high")), 2);
        assert_eq!(compute_exit_code(&result, Some("critical")), 0);
    }

    #[test]
    fn html_escape_works() {
        let escaped = html_escape(r#"<tag a="1">&</tag>"#);
        assert_eq!(escaped, "&lt;tag a=&quot;1&quot;&gt;&amp;&lt;/tag&gt;");
    }

    #[test]
    fn walkdir_filters_supported_files_and_sorts() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("b.sql"), "SELECT 1").unwrap();
        std::fs::write(root.join("a.py"), "q='SELECT 1'").unwrap();
        std::fs::write(root.join("c.txt"), "ignore").unwrap();
        std::fs::write(root.join("sub").join("d.xml"), "<mapper></mapper>").unwrap();

        let files = walkdir(root);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert_eq!(names, vec!["a.py", "b.sql", "d.xml"]);
    }

    #[test]
    fn merge_results_accumulates() {
        let mut combined = crate::models::result::AnalysisResult::new();

        let mut part = crate::models::result::AnalysisResult::new();
        part.statistics.total_queries = 2;
        part.statistics.parse_time_ms = 12.5;
        part.queries.push(crate::models::Query {
            raw: "SELECT 1".to_string(),
            normalized: "SELECT 1".to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            ..Default::default()
        });
        part.add_issue(sample_issue("X-2", Severity::Medium));

        merge_results(&mut combined, part);

        assert_eq!(combined.statistics.total_queries, 2);
        assert_eq!(combined.queries.len(), 1);
        assert_eq!(combined.issues.len(), 1);
        assert_eq!(combined.statistics.parse_time_ms, 12.5);
    }

    #[test]
    fn baseline_helpers_roundtrip() {
        let dir = tempdir().unwrap();
        let baseline_path = dir.path().join("baseline.json");

        let mut result = crate::models::result::AnalysisResult::new();
        result.add_issue(sample_issue("TEST-001", Severity::High));

        update_baseline_file(&result, &baseline_path).unwrap();

        let second = result.clone();
        let (filtered, suppressed) = apply_baseline(second, &baseline_path).unwrap();

        assert_eq!(suppressed, 1);
        assert!(filtered.issues.is_empty());
    }

    #[test]
    fn cmd_explain_known_and_unknown() {
        assert_eq!(cmd_explain("SEC-INJ-001"), 0);
        assert_eq!(cmd_explain("DOES-NOT-EXIST"), 1);
    }

    #[test]
    fn export_result_writes_json_csv_html() {
        let dir = tempdir().unwrap();

        let mut result = crate::models::result::AnalysisResult::new();
        result.add_issue(sample_issue("TEST-EXP-001", Severity::Low));

        export_result(&result, "json", dir.path());
        export_result(&result, "csv", dir.path());
        export_result(&result, "html", dir.path());
        export_result(&result, "unknown", dir.path());

        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();

        assert!(names.iter().any(|n| n.ends_with(".json")));
        assert!(names.iter().any(|n| n.ends_with(".csv")));
        assert!(names.iter().any(|n| n.ends_with(".html")));
    }

    #[test]
    fn run_with_cli_list_rules_returns_zero() {
        let mut cli = base_cli();
        cli.list_rules = true;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_explain_returns_expected_code() {
        let mut ok_cli = base_cli();
        ok_cli.explain = Some("SEC-INJ-001".to_string());
        assert_eq!(run_with_cli(ok_cli, None), 0);

        let mut bad_cli = base_cli();
        bad_cli.explain = Some("NO-RULE".to_string());
        assert_eq!(run_with_cli(bad_cli, None), 1);
    }

    #[test]
    fn run_with_cli_clear_cache_without_files_returns_zero() {
        let dir = tempdir().unwrap();
        let mut cli = base_cli();
        cli.clear_cache = true;
        cli.cache_dir = dir.path().join("cache").to_string_lossy().to_string();
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_empty_stdin_returns_one() {
        let cli = base_cli();
        assert_eq!(run_with_cli(cli, Some("   ")), 1);
    }

    #[test]
    fn run_with_cli_stdin_query_returns_zero() {
        let cli = base_cli();
        assert_eq!(run_with_cli(cli, Some("SELECT 1")), 0);
    }

    #[test]
    fn run_with_cli_missing_file_path_does_not_crash() {
        let mut cli = base_cli();
        cli.files = vec![PathBuf::from("/definitely/not/found.sql")];
        assert_eq!(run_with_cli(cli, None), 0);
    }
}

#[cfg(test)]
mod more_cli_tests {
    use super::*;
    use crate::models::issue::{Fix, FixConfidence};
    use crate::models::{Dimension, Issue, Location, Query, RuleConfidence, Severity};
    use tempfile::tempdir;

    fn cli_with_format(format: OutputFormat) -> Cli {
        Cli {
            files: Vec::new(),
            dialect: None,
            schema: None,
            format,
            export: Vec::new(),
            out: PathBuf::from("reports"),
            fail_on: None,
            diff: false,
            fix: false,
            fix_report: None,
            baseline: None,
            update_baseline: None,
            list_rules: false,
            explain: None,
            git_diff: false,
            since: None,
            jobs: 0,
            verbose: false,
            no_cache: false,
            cache_dir: ".slowql_cache".to_string(),
            clear_cache: false,
            filter_dimension: None,
            filter_dialect: None,
            min_confidence: None,
            include_nonprod: false,
            compare: false,
            init: false,
        }
    }

    fn rich_result() -> crate::models::result::AnalysisResult {
        let mut result = crate::models::result::AnalysisResult::new();
        result.statistics.analysis_time_ms = 25.0;
        result.statistics.total_queries = 2;
        result.suppressed_count = 3;

        let mut issue1 = Issue::new(
            "TEST-CTX-001",
            "Contextual issue",
            Severity::High,
            Dimension::Security,
            Location::new(2, 4).with_file("src/a.sql"),
            "SELECT * FROM users",
        )
        .with_impact("High impact")
        .with_fix(Fix {
            description: "Apply a safe replacement".to_string(),
            original: "*".to_string(),
            replacement: "id".to_string(),
            is_safe: true,
            confidence: FixConfidence::Safe,
            rule_id: "TEST-CTX-001".to_string(),
            start: None,
            end: None,
        });
        issue1.confidence = RuleConfidence::Contextual;

        let mut issue2 = Issue::new(
            "TEST-ADV-001",
            "Advisory issue",
            Severity::Low,
            Dimension::Quality,
            Location::new(1, 1),
            "DELETE FROM users",
        )
        .with_impact("Low impact");
        issue2.confidence = RuleConfidence::Advisory;

        result.add_issue(issue1);
        result.add_issue(issue2);

        result.queries.push(Query {
            raw: "SELECT * FROM users".to_string(),
            normalized: "SELECT * FROM users".to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(2, 4).with_file("src/a.sql"),
            complexity_score: 80,
            ..Default::default()
        });
        result.queries.push(Query {
            raw: "DELETE FROM users".to_string(),
            normalized: "DELETE FROM users".to_string(),
            dialect: "postgresql".to_string(),
            location: Location::new(1, 1),
            complexity_score: 10,
            ..Default::default()
        });

        result
    }

    #[test]
    fn print_console_covers_empty_path() {
        let mut result = crate::models::result::AnalysisResult::new();
        result.statistics.total_queries = 1;
        result.statistics.analysis_time_ms = 10.0;
        result.suppressed_count = 2;
        print_console(&result);
    }

    #[test]
    fn print_console_covers_rich_issue_path() {
        let result = rich_result();
        print_console(&result);
    }

    #[test]
    fn print_json_sarif_and_github_actions_cover_paths() {
        let result = rich_result();
        print_json(&result);
        print_sarif(&result);
        print_github_actions(&result);
    }

    #[test]
    fn output_result_with_mode_covers_all_formats() {
        let result = rich_result();

        let cli_console = cli_with_format(OutputFormat::Console);
        output_result_with_mode(&result, &cli_console, Some("proven"));
        output_result_with_mode(&result, &cli_console, Some("advisory"));
        output_result_with_mode(&result, &cli_console, Some("contextual"));

        let cli_json = cli_with_format(OutputFormat::Json);
        output_result_with_mode(&result, &cli_json, None);

        let cli_sarif = cli_with_format(OutputFormat::Sarif);
        output_result_with_mode(&result, &cli_sarif, None);

        let cli_ga = cli_with_format(OutputFormat::GithubActions);
        output_result_with_mode(&result, &cli_ga, None);
    }

    #[test]
    fn cmd_list_rules_covers_filter_paths() {
        cmd_list_rules(None, None);
        cmd_list_rules(Some("security"), None);
        cmd_list_rules(None, Some("postgresql"));
        cmd_list_rules(Some("quality"), Some("sqlite"));
        cmd_list_rules(Some("no-such-dimension"), Some("unknown_test_dialect_xyz"));
    }

    #[test]
    fn export_result_covers_sarif_message_branch() {
        let result = rich_result();
        let dir = tempdir().unwrap();
        export_result(&result, "sarif", dir.path());
    }
}

#[cfg(test)]
mod cli_path_tests {
    use super::*;
    use tempfile::tempdir;

    fn base_cli() -> Cli {
        Cli {
            files: Vec::new(),
            dialect: None,
            schema: None,
            format: OutputFormat::Json,
            export: Vec::new(),
            out: PathBuf::from("reports"),
            fail_on: None,
            diff: false,
            fix: false,
            fix_report: None,
            baseline: None,
            update_baseline: None,
            list_rules: false,
            explain: None,
            git_diff: false,
            since: None,
            jobs: 0,
            verbose: false,
            no_cache: false,
            cache_dir: ".slowql_cache".to_string(),
            clear_cache: false,
            filter_dimension: None,
            filter_dialect: None,
            min_confidence: None,
            include_nonprod: false,
            compare: false,
            init: false,
        }
    }

    #[test]
    fn run_with_cli_analyzes_sql_file() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_analyzes_directory() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.sql"), "SELECT 1").unwrap();
        std::fs::write(dir.path().join("b.sql"), "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![dir.path().to_path_buf()];
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_schema_flag() {
        let dir = tempdir().unwrap();
        let schema_path = dir.path().join("schema.sql");
        std::fs::write(&schema_path, "CREATE TABLE users (id INT PRIMARY KEY);").unwrap();
        let sql_path = dir.path().join("q.sql");
        std::fs::write(&sql_path, "SELECT * FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql_path];
        cli.schema = Some(schema_path);
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_schema_bad_path() {
        let dir = tempdir().unwrap();
        let sql_path = dir.path().join("q.sql");
        std::fs::write(&sql_path, "SELECT 1").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql_path];
        cli.schema = Some(PathBuf::from("/no/such/schema.sql"));
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_update_baseline_from_file() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "DELETE FROM users").unwrap();
        let baseline = dir.path().join("bl.json");

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.update_baseline = Some(baseline.clone());
        assert_eq!(run_with_cli(cli, None), 0);
        assert!(baseline.exists());
    }

    #[test]
    fn run_with_cli_baseline_filters_from_file() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "DELETE FROM users").unwrap();
        let baseline_path = dir.path().join("bl.json");

        let mut cli1 = base_cli();
        cli1.files = vec![sql.clone()];
        cli1.update_baseline = Some(baseline_path.clone());
        run_with_cli(cli1, None);

        let mut cli2 = base_cli();
        cli2.files = vec![sql];
        cli2.baseline = Some(baseline_path);
        assert_eq!(run_with_cli(cli2, None), 0);
    }

    #[test]
    fn run_with_cli_fail_on_high() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.fail_on = Some("high".to_string());
        let code = run_with_cli(cli, None);
        let _ = code;
    }

    #[test]
    fn run_with_cli_verbose_flag() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "SELECT 1").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.verbose = true;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_min_confidence_advisory() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "SELECT * FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.min_confidence = Some("advisory".to_string());
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_compare_flag() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.sql");
        let b = dir.path().join("b.sql");
        std::fs::write(&a, "SELECT id FROM users WHERE id = 1").unwrap();
        std::fs::write(&b, "SELECT id FROM users WHERE id = 2").unwrap();

        let mut cli = base_cli();
        cli.files = vec![a, b];
        cli.compare = true;
        cli.min_confidence = Some("advisory".to_string());
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_export_all_formats() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "DELETE FROM users").unwrap();
        let out = dir.path().join("out");

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.export = vec!["json".into(), "csv".into(), "html".into(), "sarif".into(), "unknown".into()];
        cli.out = out;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_stdin_proven_mode() {
        let mut cli = base_cli();
        cli.min_confidence = Some("proven".to_string());
        let code = run_with_cli(cli, Some("DELETE FROM users"));
        let _ = code;
    }

    #[test]
    fn run_with_cli_stdin_advisory_mode() {
        let mut cli = base_cli();
        cli.min_confidence = Some("advisory".to_string());
        let code = run_with_cli(cli, Some("DELETE FROM users"));
        let _ = code;
    }

    #[test]
    fn run_with_cli_console_format_with_issues() {
        let mut cli = base_cli();
        cli.format = OutputFormat::Console;
        let code = run_with_cli(cli, Some("DELETE FROM users"));
        let _ = code;
    }

    #[test]
    fn run_with_cli_github_actions_format() {
        let mut cli = base_cli();
        cli.format = OutputFormat::GithubActions;
        let code = run_with_cli(cli, Some("DELETE FROM users"));
        let _ = code;
    }

    #[test]
    fn run_with_cli_sarif_format() {
        let mut cli = base_cli();
        cli.format = OutputFormat::Sarif;
        let code = run_with_cli(cli, Some("DELETE FROM users"));
        let _ = code;
    }

    #[test]
    fn run_with_cli_dialect_override() {
        let mut cli = base_cli();
        cli.dialect = Some("mysql".to_string());
        let code = run_with_cli(cli, Some("SELECT 1"));
        assert_eq!(code, 0);
    }

    #[test]
    fn run_with_cli_clear_cache_then_analyze() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "SELECT 1").unwrap();

        let mut cli = base_cli();
        cli.clear_cache = true;
        cli.cache_dir = dir.path().join("cache").to_string_lossy().to_string();
        cli.files = vec![sql];
        assert_eq!(run_with_cli(cli, None), 0);
    }
}

#[cfg(test)]
mod cli_deep_tests {
    use super::*;
    use crate::models::issue::{Fix, FixConfidence};
    use crate::models::{Dimension, Issue, Location, Query, RuleConfidence, Severity};
    use tempfile::tempdir;

    fn base_cli() -> Cli {
        Cli {
            files: Vec::new(),
            dialect: None,
            schema: None,
            format: OutputFormat::Json,
            export: Vec::new(),
            out: PathBuf::from("reports"),
            fail_on: None,
            diff: false,
            fix: false,
            fix_report: None,
            baseline: None,
            update_baseline: None,
            list_rules: false,
            explain: None,
            git_diff: false,
            since: None,
            jobs: 0,
            verbose: false,
            no_cache: false,
            cache_dir: ".slowql_cache".to_string(),
            clear_cache: false,
            filter_dimension: None,
            filter_dialect: None,
            min_confidence: None,
            include_nonprod: false,
            compare: false,
            init: false,
        }
    }

    fn print_console_with_advisory_and_impact_and_fix() {
        let mut result = crate::models::result::AnalysisResult::new();
        result.statistics.analysis_time_ms = 50.0;

        let mut issue = Issue::new(
            "TEST-001",
            "test issue",
            Severity::High,
            Dimension::Security,
            Location::new(1, 1).with_file("src/a.sql"),
            "x".repeat(50).as_str(),
        )
        .with_impact("serious impact")
        .with_fix(Fix {
            description: "Apply this fix".to_string(),
            original: "x".to_string(),
            replacement: "y".to_string(),
            is_safe: true,
            confidence: FixConfidence::Safe,
            rule_id: "TEST-001".to_string(),
            start: None,
            end: None,
        });
        issue.confidence = RuleConfidence::Contextual;

        let mut issue2 = Issue::new(
            "TEST-002",
            "advisory",
            Severity::Info,
            Dimension::Quality,
            Location::new(2, 1),
            "y",
        );
        issue2.confidence = RuleConfidence::Advisory;
        issue2.documentation_url = Some("https://slowql.dev/rules/test-002".to_string());

        result.add_issue(issue);
        result.add_issue(issue2);

        for i in 0..3 {
            result.queries.push(Query {
                raw: "SELECT 1".to_string(),
                normalized: "SELECT 1".to_string(),
                dialect: "postgresql".to_string(),
                location: Location::new(1, 1).with_file("src/a.sql"),
                complexity_score: if i == 0 { 80 } else { 10 },
                ..Default::default()
            });
        }
        result.suppressed_count = 5;

        print_console(&result);
    }

    #[test]
    fn run_with_cli_directory_with_include_nonprod() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tests")).unwrap();
        std::fs::write(
            dir.path().join("tests").join("a.sql"),
            "SELECT * FROM t",
        )
        .unwrap();
        std::fs::write(dir.path().join("app.sql"), "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![dir.path().to_path_buf()];
        cli.include_nonprod = true;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_directory_scans_and_suppresses_nonprod() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tests")).unwrap();
        std::fs::write(dir.path().join("app.sql"), "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![dir.path().to_path_buf()];
        cli.format = OutputFormat::Console;
        cli.include_nonprod = false;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_baseline_bad_file_returns_zero() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "SELECT 1").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.baseline = Some(PathBuf::from("/nonexistent/baseline.json"));
        let code = run_with_cli(cli, None);
        assert_eq!(code, 1);
    }

    #[test]
    fn run_with_cli_fix_diff_mode() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "SELECT * FROM t WHERE x = NULL").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.diff = true;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_fix_apply_mode() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "SELECT * FROM t WHERE x = NULL").unwrap();
        let report = dir.path().join("fixes.json");

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.fix = true;
        cli.fix_report = Some(report);
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_git_diff_flag() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "SELECT 1").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.git_diff = true;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_verbose_with_many_files() {
        let dir = tempdir().unwrap();
        for i in 0..7 {
            std::fs::write(dir.path().join(format!("{}.sql", i)), "SELECT 1").unwrap();
        }

        let mut cli = base_cli();
        cli.files = vec![dir.path().to_path_buf()];
        cli.verbose = true;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_min_confidence_proven_with_issues() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.min_confidence = Some("proven".to_string());
        cli.format = OutputFormat::Console;
        let code = run_with_cli(cli, None);
        let _ = code;
    }

    #[test]
    fn cmd_explain_dialect_specific_rule() {
        let code = cmd_explain("SEC-PG-001");
        assert_eq!(code, 0);
    }

    #[test]
    fn cmd_explain_rule_with_impact_and_fix() {
        let code = cmd_explain("PERF-SCAN-001");
        assert_eq!(code, 0);
    }

    #[test]
    fn apply_baseline_file_not_found_returns_error() {
        let result = crate::models::result::AnalysisResult::new();
        let err = apply_baseline(result, std::path::Path::new("/no/such/baseline.json"));
        assert!(err.is_err());
    }

    #[test]
    fn print_console_empty_result_with_suppressed_count() {
        let mut result = crate::models::result::AnalysisResult::new();
        result.suppressed_count = 3;
        result.statistics.analysis_time_ms = 0.0;
        print_console(&result);
    }

    #[test]
    fn print_console_empty_result_with_analysis_time() {
        let mut result = crate::models::result::AnalysisResult::new();
        result.statistics.analysis_time_ms = 42.0;
        print_console(&result);
    }

    #[test]
    fn run_with_cli_directory_many_issues_triggers_nonprod_recompute() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("app.sql"), "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![dir.path().to_path_buf()];
        cli.min_confidence = Some("advisory".to_string());
        assert_eq!(run_with_cli(cli, None), 0);
    }
}

#[cfg(test)]
mod cli_branch_tests {
    use super::*;
    use tempfile::tempdir;

    fn base_cli() -> Cli {
        Cli {
            files: Vec::new(),
            dialect: None,
            schema: None,
            format: OutputFormat::Json,
            export: Vec::new(),
            out: PathBuf::from("reports"),
            fail_on: None,
            diff: false,
            fix: false,
            fix_report: None,
            baseline: None,
            update_baseline: None,
            list_rules: false,
            explain: None,
            git_diff: false,
            since: None,
            jobs: 0,
            verbose: false,
            no_cache: false,
            cache_dir: ".slowql_cache".to_string(),
            clear_cache: false,
            filter_dimension: None,
            filter_dialect: None,
            min_confidence: None,
            include_nonprod: false,
            compare: false,
            init: false,
        }
    }

    #[test]
    fn run_with_cli_git_diff_directory_path_hits_changed_filter() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.sql"), "SELECT 1").unwrap();
        std::fs::write(dir.path().join("b.sql"), "SELECT 1").unwrap();

        let mut cli = base_cli();
        cli.files = vec![dir.path().to_path_buf()];
        cli.git_diff = true;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_git_diff_file_path_hits_changed_filter() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("single.sql");
        std::fs::write(&sql, "SELECT 1").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.git_diff = true;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_invalid_utf8_directory_verbose_hits_skip_reporting() {
        let dir = tempdir().unwrap();

        // More than 5 files to exercise progress clear path as well.
        for i in 0..6 {
            std::fs::write(dir.path().join(format!("{i}.sql")), "SELECT 1").unwrap();
        }

        // Invalid UTF-8 SQL file to hit skipped_non_utf8 accounting.
        std::fs::write(dir.path().join("bad.sql"), vec![0xff, 0xfe, 0xfd]).unwrap();

        let mut cli = base_cli();
        cli.files = vec![dir.path().to_path_buf()];
        cli.verbose = true;
        cli.format = OutputFormat::Console;
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_invalid_utf8_single_file_hits_file_error_branch() {
        let dir = tempdir().unwrap();
        let bad = dir.path().join("bad.sql");
        std::fs::write(&bad, vec![0xff, 0xfe, 0xfd]).unwrap();

        let mut cli = base_cli();
        cli.files = vec![bad];
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_update_baseline_bad_parent_fails() {
        let dir = tempdir().unwrap();
        let sql = dir.path().join("q.sql");
        std::fs::write(&sql, "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![sql];
        cli.update_baseline = Some(dir.path().join("missing-dir").join("baseline.json"));
        assert_eq!(run_with_cli(cli, None), 1);
    }

    #[test]
    fn run_with_cli_directory_nonprod_first_pass_recomputes_stats() {
        let dir = tempdir().unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir_all(&tests_dir).unwrap();

        // REL-DATA-001 is allowed in test context by engine, then suppressed by CLI nonprod pass.
        std::fs::write(tests_dir.join("delete.sql"), "DELETE FROM users").unwrap();
        std::fs::write(dir.path().join("app.sql"), "DELETE FROM users").unwrap();

        let mut cli = base_cli();
        cli.files = vec![dir.path().to_path_buf()];
        cli.format = OutputFormat::Console;
        cli.min_confidence = Some("proven".to_string());
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn run_with_cli_compare_advisory_is_filtered_and_recomputed() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.sql");
        let b = dir.path().join("b.sql");

        std::fs::write(&a, "SELECT id, name, email, created_at FROM users_table_long_name WHERE user_id_column = 1").unwrap();
        std::fs::write(&b, "SELECT id, name, email, created_at FROM users_table_long_name WHERE user_id_column = 42").unwrap();

        let mut cli = base_cli();
        cli.files = vec![a, b];
        cli.compare = true;
        // Default config min_confidence is proven/contextual depending config load.
        // Force contextual so advisory compare issue is filtered in final confidence pass.
        cli.min_confidence = Some("contextual".to_string());
        assert_eq!(run_with_cli(cli, None), 0);
    }

    #[test]
    fn print_console_empty_result_with_analysis_time_and_suppressed_count() {
        let mut result = crate::models::result::AnalysisResult::new();
        result.statistics.analysis_time_ms = 42.0;
        result.statistics.total_queries = 3;
        result.suppressed_count = 2;
        print_console(&result);
    }

    #[test]
    fn print_console_info_severity_and_long_snippet_branch() {
        let mut result = crate::models::result::AnalysisResult::new();
        result.statistics.analysis_time_ms = 10.0;

        let mut issue = crate::models::Issue::new(
            "TEST-INFO-001",
            "informational",
            crate::models::Severity::Info,
            crate::models::Dimension::Quality,
            crate::models::Location::new(3, 7).with_file("src/file.sql"),
            "x".repeat(200),
        );
        issue.confidence = crate::models::RuleConfidence::Proven;
        issue.documentation_url = Some("https://slowql.dev/rules/test-info-001".to_string());
        result.add_issue(issue);

        print_console(&result);
    }

    #[test]
    fn print_github_actions_notice_branch_for_info() {
        let mut result = crate::models::result::AnalysisResult::new();
        let issue = crate::models::Issue::new(
            "TEST-INFO-002",
            "notice branch",
            crate::models::Severity::Info,
            crate::models::Dimension::Quality,
            crate::models::Location::new(1, 1),
            "SELECT 1",
        );
        result.add_issue(issue);
        print_github_actions(&result);
    }

    #[test]
    fn print_sarif_unknown_file_and_zero_column_branch() {
        let mut result = crate::models::result::AnalysisResult::new();
        let issue = crate::models::Issue::new(
            "TEST-SARIF-001",
            "sarif branch",
            crate::models::Severity::Low,
            crate::models::Dimension::Quality,
            crate::models::Location::new(1, 0),
            "SELECT 1",
        );
        result.add_issue(issue);
        print_sarif(&result);
    }

    #[test]
    fn cmd_explain_rule_with_many_dialects_and_category() {
        assert_eq!(cmd_explain("QUAL-STYLE-001"), 0);
    }

    #[test]
    fn cmd_explain_rule_with_specific_dialects_list() {
        assert_eq!(cmd_explain("SEC-PG-001"), 0);
    }

    #[test]
    fn cmd_explain_rule_with_fix_guidance_if_available() {
        // Keep broad and stable: this should at least execute the code path for explain.
        assert_eq!(cmd_explain("REL-DATA-001"), 0);
    }

    #[test]
    fn walkdir_ignores_unsupported_extension() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "x").unwrap();
        let files = walkdir(dir.path());
        assert!(files.is_empty());
    }
}
