#[test]
fn binary_wrapper_list_rules_runs() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_slowql"))
        .arg("--list-rules")
        .output()
        .expect("binary should run");

    assert!(output.status.success());
}
