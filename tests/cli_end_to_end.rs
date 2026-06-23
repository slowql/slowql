use serde_json::Value;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::tempdir;

/// Run the compiled slowql binary in an isolated working directory.
/// This keeps CLI behavior testable without mutating process-global state.
fn run_slowql(cwd: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_slowql"));
    cmd.current_dir(cwd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }

    let mut child = cmd.spawn().expect("failed to spawn slowql");

    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin pipe missing")
            .write_all(input.as_bytes())
            .expect("failed to write stdin");
    }

    child.wait_with_output().expect("failed to wait on slowql")
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be utf8")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be utf8")
}

#[test]
fn cli_explain_known_rule_succeeds() {
    let dir = tempdir().unwrap();
    let output = run_slowql(dir.path(), &["--explain", "SEC-INJ-001"], None);

    assert!(output.status.success());
    let stdout = stdout_text(&output);
    assert!(stdout.contains("Rule:"));
    assert!(stdout.contains("SEC-INJ-001"));
}

#[test]
fn cli_explain_unknown_rule_fails() {
    let dir = tempdir().unwrap();
    let output = run_slowql(dir.path(), &["--explain", "NO-SUCH-RULE"], None);

    assert!(!output.status.success());
    let stderr = stderr_text(&output);
    assert!(stderr.contains("Rule not found"));
}

#[test]
fn cli_init_creates_config_and_second_run_fails() {
    let dir = tempdir().unwrap();

    let first = run_slowql(
        dir.path(),
        &["--init", "--dialect", "sqlite", "--fail-on", "low"],
        None,
    );
    assert!(first.status.success());

    let config_path = dir.path().join("slowql.yaml");
    assert!(config_path.exists());

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("dialect: sqlite"));
    assert!(content.contains("fail_on: low"));

    let second = run_slowql(dir.path(), &["--init"], None);
    assert!(!second.status.success());
    assert!(stderr_text(&second).contains("already exists"));
}

#[test]
fn cli_clear_cache_without_files_succeeds() {
    let dir = tempdir().unwrap();
    let cache_dir = dir.path().join("cache");

    let output = run_slowql(
        dir.path(),
        &["--clear-cache", "--cache-dir", cache_dir.to_str().unwrap()],
        None,
    );

    assert!(output.status.success());
    assert!(stderr_text(&output).contains("Cache cleared"));
}

#[test]
fn cli_empty_stdin_fails_with_usage() {
    let dir = tempdir().unwrap();
    let output = run_slowql(dir.path(), &[], Some("   \n"));

    assert!(!output.status.success());
    let stderr = stderr_text(&output);
    assert!(stderr.contains("Usage: slowql"));
}

#[test]
fn cli_json_output_from_stdin_is_valid_json() {
    let dir = tempdir().unwrap();
    let output = run_slowql(dir.path(), &["--format", "json"], Some("SELECT 1"));

    assert!(output.status.success());
    let json: Value = serde_json::from_str(&stdout_text(&output)).unwrap();
    assert_eq!(json["statistics"]["total_queries"].as_u64(), Some(1));
}

#[test]
fn cli_sarif_output_from_stdin_is_valid_shape() {
    let dir = tempdir().unwrap();
    let output = run_slowql(
        dir.path(),
        &["--format", "sarif"],
        Some("DELETE FROM users"),
    );

    let stdout = stdout_text(&output);
    assert!(stdout.contains("\"version\": \"2.1.0\""));
    assert!(stdout.contains("\"runs\""));
}

#[test]
fn cli_github_actions_output_from_stdin_contains_annotations() {
    let dir = tempdir().unwrap();
    let output = run_slowql(
        dir.path(),
        &["--format", "github-actions"],
        Some("DELETE FROM users"),
    );

    let stdout = stdout_text(&output);
    assert!(stdout.contains("::"));
    assert!(stdout.contains("REL-DATA-001") || stdout.contains("PERF-") || stdout.contains("SEC-"));
}

#[test]
fn cli_export_json_csv_html_creates_files() {
    let dir = tempdir().unwrap();
    let sql_path = dir.path().join("query.sql");
    let out_dir = dir.path().join("reports");

    std::fs::write(&sql_path, "DELETE FROM users").unwrap();

    let output = run_slowql(
        dir.path(),
        &[
            sql_path.to_str().unwrap(),
            "--export",
            "json",
            "--export",
            "csv",
            "--export",
            "html",
            "--out",
            out_dir.to_str().unwrap(),
        ],
        None,
    );

    assert!(output.status.success());

    let names: Vec<String> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();

    assert!(names.iter().any(|n| n.ends_with(".json")));
    assert!(names.iter().any(|n| n.ends_with(".csv")));
    assert!(names.iter().any(|n| n.ends_with(".html")));
}

#[test]
fn cli_update_baseline_creates_file() {
    let dir = tempdir().unwrap();
    let sql_path = dir.path().join("query.sql");
    let baseline_path = dir.path().join("baseline.json");

    std::fs::write(&sql_path, "DELETE FROM users").unwrap();

    let output = run_slowql(
        dir.path(),
        &[
            sql_path.to_str().unwrap(),
            "--update-baseline",
            baseline_path.to_str().unwrap(),
        ],
        None,
    );

    assert!(output.status.success());
    assert!(baseline_path.exists());
}

#[test]
fn cli_baseline_filters_existing_issues() {
    let dir = tempdir().unwrap();
    let sql_path = dir.path().join("query.sql");
    let baseline_path = dir.path().join("baseline.json");

    std::fs::write(&sql_path, "DELETE FROM users").unwrap();

    let update = run_slowql(
        dir.path(),
        &[
            sql_path.to_str().unwrap(),
            "--update-baseline",
            baseline_path.to_str().unwrap(),
        ],
        None,
    );
    assert!(update.status.success());

    let run = run_slowql(
        dir.path(),
        &[
            sql_path.to_str().unwrap(),
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--format",
            "json",
        ],
        None,
    );

    assert!(run.status.success());
    let json: Value = serde_json::from_str(&stdout_text(&run)).unwrap();
    assert_eq!(json["statistics"]["total_issues"].as_u64(), Some(0));
    assert!(json["suppressed_count"].as_u64().unwrap_or(0) >= 1);
}

#[test]
fn cli_compare_detects_similar_queries_across_files() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.sql");
    let b = dir.path().join("b.sql");

    std::fs::write(&a, "SELECT id, name, email, created_at FROM users_table_long_name WHERE user_id_column = 1").unwrap();
    std::fs::write(&b, "SELECT id, name, email, created_at FROM users_table_long_name WHERE user_id_column = 42").unwrap();

    let output = run_slowql(
        dir.path(),
        &[
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--compare",
            "--min-confidence",
            "advisory",
            "--format",
            "json",
        ],
        None,
    );

    assert!(output.status.success());
    let json: Value = serde_json::from_str(&stdout_text(&output)).unwrap();
    let issues = json["issues"].as_array().unwrap();
    assert!(issues.iter().any(|i| i["rule_id"] == "QUAL-COMPARE-001"));
}

#[test]
fn cli_missing_file_path_does_not_fail_process() {
    let dir = tempdir().unwrap();
    let output = run_slowql(dir.path(), &["does-not-exist.sql"], None);

    assert!(output.status.success());
    assert!(stderr_text(&output).contains("File not found"));
}
