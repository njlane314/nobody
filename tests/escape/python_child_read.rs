#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::common::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn python_child_read_is_denied() {
    if !command_available("python3") {
        eprintln!("skipping python_child_read: python3 not found");
        return;
    }
    let python = command_path("python3");

    let dir = EscapeDir::new("python-child-read");
    write(dir.path().join(".env"), "SECRET=1\n");
    #[cfg(target_os = "macos")]
    mkdir(dir.path().join("tmp"));

    #[cfg(target_os = "linux")]
    dir.write_policy_with_process_rules(
        &[],
        &[],
        &[".env"],
        &["python3"],
        r#"
[[process.rule]]
program = "python3"
allow_args = ["-c"]
"#,
    );

    #[cfg(target_os = "macos")]
    dir.write_policy_with_process_rules(
        &["."],
        &["./tmp"],
        &[".env"],
        &["python3"],
        r#"
[[process.rule]]
program = "python3"
allow_args = ["-c"]
"#,
    );

    #[cfg(target_os = "linux")]
    let output = run_nobody(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            &python,
            "-c",
            r#"import pathlib, sys
try:
    pathlib.Path(".env").read_text()
except OSError:
    print("denied-python")
else:
    sys.exit(7)
"#,
        ],
    );

    #[cfg(target_os = "macos")]
    let output = run_nobody_with_env(
        dir.path(),
        &[("TMPDIR", dir.path().join("tmp").as_path())],
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            &python,
            "-c",
            r#"import pathlib, sys
try:
    pathlib.Path(".env").read_text()
except OSError:
    print("denied-python")
else:
    sys.exit(7)
"#,
        ],
    );

    assert_denied(&output, "denied-python");
}
