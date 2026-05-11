#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn write_outside_repo_is_denied() {
    let dir = EscapeDir::new("write-outside-repo");
    mkdir(dir.path().join("work"));
    dir.write_policy_with_process_rules(
        &[],
        &["./work"],
        &[],
        &["sh"],
        r#"
[[process.rule]]
program = "sh"
allow_args = ["-c"]
"#,
    );

    let output = run_nobody(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "sh",
            "-c",
            r#"if echo x > ../outside.txt; then exit 7; else echo denied-write; fi"#,
        ],
    );

    assert_denied(&output, "denied-write");
    assert!(!dir.path().parent().unwrap().join("outside.txt").exists());
}
