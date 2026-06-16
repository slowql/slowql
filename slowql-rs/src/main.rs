use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::process;

use slowql_lib::config::Config;
use slowql_lib::engine::Engine;

#[derive(Parser)]
#[command(name = "slowql", version, about = "Next-generation SQL static analyzer")]
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

    /// Filter --list-rules by dimension
    #[arg(long)]
    filter_dimension: Option<String>,

    /// Filter --list-rules by dialect
    #[arg(long)]
    filter_dialect: Option<String>,

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
    result: slowql_lib::models::result::AnalysisResult,
    baseline_path: &std::path::Path,
) -> Result<(slowql_lib::models::result::AnalysisResult, usize), String> {
    let baseline = slowql_lib::baseline::Baseline::load(baseline_path)?;
    Ok(slowql_lib::baseline::Baseline::filter_new(result, &baseline))
}

fn update_baseline_file(
    result: &slowql_lib::models::result::AnalysisResult,
    baseline_path: &std::path::Path,
) -> Result<(), String> {
    let baseline = slowql_lib::baseline::Baseline::generate(result);
    baseline.save(baseline_path)
}

fn main() {
    let cli = Cli::parse();

    // Handle --list-rules
    if cli.list_rules {
        cmd_list_rules(cli.filter_dimension.as_deref(), cli.filter_dialect.as_deref());
        process::exit(0);
    }

    // Handle --explain
    if let Some(rule_id) = &cli.explain {
        let code = cmd_explain(rule_id);
        process::exit(code);
    }

    // Handle --init
    if cli.init {
        eprintln!("slowql init: not yet implemented in Rust port");
        process::exit(1);
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

    let _schema = cli.schema.as_ref().map(|path| {
        let dialect = cli.dialect.as_deref().unwrap_or("postgresql");
        match slowql_lib::schema::load_schema_file(path, dialect) {
            Ok(s) => {
                eprintln!("Schema loaded: {} tables from {}", s.tables.len(), path.display());
                Some(s)
            }
            Err(e) => {
                eprintln!("Warning: {}", e);
                None
            }
        }
    }).flatten();

    let engine = Engine::new(config);

    // Determine input
    if cli.files.is_empty() {
        // Read from stdin
        let mut sql = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut sql).unwrap_or_else(|e| {
            eprintln!("Error reading stdin: {}", e);
            process::exit(1);
        });
        if sql.trim().is_empty() {
            eprintln!("Usage: slowql <file.sql> [options]");
            eprintln!("       cat queries.sql | slowql");
            process::exit(1);
        }
        let result = engine.analyze(&sql, cli.dialect.as_deref(), None);
        output_result(&result, &cli);
        process::exit(compute_exit_code(&result, cli.fail_on.as_deref()));
    }

    // Analyze files
    let mut combined = slowql_lib::models::result::AnalysisResult::new();
    combined.dialect = cli.dialect.clone();

    let changed_files = if cli.git_diff || cli.since.is_some() {
        Some(slowql_lib::git::get_changed_files(cli.since.as_deref()))
    } else {
        None
    };

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
                match engine.analyze_file(entry.to_str().unwrap_or("")) {
                    Ok(result) => merge_results(&mut combined, result),
                    Err(e) => eprintln!("Warning: {}", e),
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
            match engine.analyze_file(path.to_str().unwrap_or("")) {
                Ok(result) => merge_results(&mut combined, result),
                Err(e) => eprintln!("Error: {}", e),
            }
        } else {
            eprintln!("File not found: {}", path.display());
        }
    }

    if let Some(ref baseline_out) = cli.update_baseline {
        if let Err(e) = update_baseline_file(&combined, baseline_out) {
            eprintln!("Error writing baseline: {}", e);
            process::exit(1);
        }
        eprintln!("Baseline updated: {}", baseline_out.display());
        process::exit(0);
    }

    let mut final_result = combined;
    if let Some(ref baseline_in) = cli.baseline {
        match apply_baseline(final_result, baseline_in) {
            Ok((filtered, suppressed)) => {
                final_result = filtered;
                final_result.suppressed_count += suppressed;
            }
            Err(e) => {
                eprintln!("Error loading baseline: {}", e);
                process::exit(1);
            }
        }
    }

    output_result(&final_result, &cli);

    for fmt in &cli.export {
        export_result(&final_result, fmt, &cli.out);
    }

    process::exit(compute_exit_code(&final_result, cli.fail_on.as_deref()));
}

fn merge_results(
    combined: &mut slowql_lib::models::result::AnalysisResult,
    result: slowql_lib::models::result::AnalysisResult,
) {
    for issue in result.issues {
        combined.add_issue(issue);
    }
    combined.queries.extend(result.queries);
    combined.statistics.total_queries += result.statistics.total_queries;
    combined.statistics.parse_time_ms += result.statistics.parse_time_ms;
}

fn output_result(result: &slowql_lib::models::result::AnalysisResult, cli: &Cli) {
    match cli.format {
        OutputFormat::Console => print_console(result),
        OutputFormat::Json => print_json(result),
        OutputFormat::Sarif => print_sarif(result),
        OutputFormat::GithubActions => print_github_actions(result),
    }
}

fn print_console(result: &slowql_lib::models::result::AnalysisResult) {

    if result.issues.is_empty() {
        println!("\x1b[1;32mNo issues found.\x1b[0m");
        println!("  Scanned {} queries", result.statistics.total_queries);
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
        let count = result.statistics.by_severity.get(*sev).copied().unwrap_or(0);
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

    // Issues sorted by severity
    let sorted = result.sorted_by_severity();
    for issue in sorted {
        let color = issue.severity.color_code();
        let reset = "\x1b[0m";

        let loc = if let Some(ref file) = issue.location.file {
            format!("{}:{}:{}", file, issue.location.line, issue.location.column)
        } else {
            format!("{}:{}", issue.location.line, issue.location.column)
        };

        println!(
            "  {}{:>8}{} {} {} {}",
            color,
            issue.severity.as_str().to_uppercase(),
            reset,
            issue.rule_id,
            loc,
            issue.message
        );

        if let Some(ref impact) = issue.impact {
            println!("           \x1b[2m{}\x1b[0m", impact);
        }

        if let Some(ref fix) = issue.fix {
            if !fix.description.is_empty() {
                println!("           \x1b[32mFix: {}\x1b[0m", fix.description);
            }
        }
    }
    println!();
}

fn print_json(result: &slowql_lib::models::result::AnalysisResult) {
    match serde_json::to_string_pretty(result) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing to JSON: {}", e),
    }
}

fn print_sarif(result: &slowql_lib::models::result::AnalysisResult) {
    let mut rules_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
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
            slowql_lib::models::Severity::Critical | slowql_lib::models::Severity::High => "error",
            slowql_lib::models::Severity::Medium => "warning",
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
            region.insert("startColumn".into(), serde_json::json!(issue.location.column));
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

    println!("{}", serde_json::to_string_pretty(&sarif).unwrap_or_default());
}

fn print_github_actions(result: &slowql_lib::models::result::AnalysisResult) {
    for issue in &result.issues {
        let level = match issue.severity {
            slowql_lib::models::Severity::Critical | slowql_lib::models::Severity::High => "error",
            slowql_lib::models::Severity::Medium | slowql_lib::models::Severity::Low => "warning",
            slowql_lib::models::Severity::Info => "notice",
        };

        let file = issue.location.file.as_deref().unwrap_or("");
        let line = issue.location.line;
        let col = issue.location.column;

        let msg = issue.message.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A");

        if !file.is_empty() {
            println!("::{level} file={file},line={line},col={col}::{} {msg}", issue.rule_id);
        } else {
            println!("::{level}::{} {msg}", issue.rule_id);
        }
    }
}

fn export_result(
    result: &slowql_lib::models::result::AnalysisResult,
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
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn compute_exit_code(
    result: &slowql_lib::models::result::AnalysisResult,
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

    let max_weight = result.issues.iter().map(|i| i.severity.weight()).max().unwrap_or(0);
    if max_weight >= threshold { 2 } else { 0 }
}

fn cmd_list_rules(dimension: Option<&str>, _dialect: Option<&str>) {
    let engine = Engine::with_default_config();
    let rules = engine.registry_ref().all();

    println!("SlowQL Rules ({})", rules.len());
    println!("{:<18} {:<8} {:<14} {}", "Rule ID", "Severity", "Dimension", "Name");
    println!("{}", "-".repeat(70));

    for rule in rules {
        if let Some(dim) = dimension {
            if rule.dimension().as_str() != dim {
                continue;
            }
        }
        println!(
            "{:<18} {:<8} {:<14} {}",
            rule.id(),
            rule.severity().as_str(),
            rule.dimension().as_str(),
            rule.name()
        );
    }
}

fn cmd_explain(rule_id: &str) -> i32 {
    let engine = Engine::with_default_config();
    let rules = engine.registry_ref().all();

    if let Some(rule) = rules.iter().find(|r| r.id().eq_ignore_ascii_case(rule_id)) {
        println!("Rule:      {}", rule.id());
        println!("Name:      {}", rule.name());
        println!("Severity:  {}", rule.severity().as_str());
        println!("Dimension: {}", rule.dimension().as_str());
        if !rule.impact().is_empty() {
            println!("Impact:    {}", rule.impact());
        }
        if !rule.fix_guidance().is_empty() {
            println!("Fix:       {}", rule.fix_guidance());
        }
        0
    } else {
        eprintln!("Rule not found: {}", rule_id);
        1
    }
}

fn walkdir(path: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let supported = ["sql", "py", "ts", "js", "java", "go", "rb", "kt", "cs"];
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
