#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::common::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn read_dotenv_is_denied() {
    let dir = EscapeDir::new("read-dotenv");
    write(dir.path().join(".env"), "SECRET=1\n");
    dir.write_policy_with_process_rules(
        &[],
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
            r#"if cat .env; then exit 7; else echo denied-dotenv; fi"#,
        ],
    );

    assert_denied(&output, "denied-dotenv");
    #[cfg(target_os = "linux")]
    assert!(dir.trace().contains(r#""backend":"landlock""#));
    #[cfg(target_os = "macos")]
    assert!(dir.trace().contains(r#""backend":"sandbox-exec""#));
    assert!(dir.trace().contains(r#""enforced":true"#));
}
