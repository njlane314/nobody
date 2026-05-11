#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn read_dotenv_is_denied() {
    let dir = EscapeDir::new("read-dotenv");
    write(dir.path().join(".env"), "SECRET=1\n");
    dir.write_policy(&[], &[], &[".env"], &["sh"]);

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
    assert!(dir.trace().contains(r#""backend":"landlock""#));
    assert!(dir.trace().contains(r#""enforced":true"#));
}
