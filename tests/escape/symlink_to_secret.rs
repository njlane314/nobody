#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn symlink_to_secret_is_denied() {
    let dir = EscapeDir::new("symlink-to-secret");
    mkdir(dir.path().join("work"));
    write(dir.path().join(".env"), "SECRET=1\n");
    symlink_file(
        dir.path().join(".env"),
        dir.path().join("work/symlink-to-env"),
    )
    .unwrap();
    dir.write_policy(&["./work"], &[], &[".env"], &["sh"]);

    let output = run_nobody(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "sh",
            "-c",
            r#"if cat work/symlink-to-env; then exit 7; else echo denied-symlink; fi"#,
        ],
    );

    assert_denied(&output, "denied-symlink");
}
