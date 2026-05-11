#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::common::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn parent_dir_traversal_to_secret_is_denied() {
    let dir = EscapeDir::new("parent-dir-traversal");
    mkdir(dir.path().join("src"));
    write(dir.path().join(".env"), "SECRET=1\n");
    dir.write_policy_with_process_rules(
        &["./src"],
        &[],
        &[".env"],
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
            r#"if cat ./src/../.env; then exit 7; else echo denied-traversal; fi"#,
        ],
    );

    assert_denied(&output, "denied-traversal");
}
