#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn bash_child_read_is_denied() {
    if !command_available("bash") {
        eprintln!("skipping bash_child_read: bash not found");
        return;
    }

    let dir = EscapeDir::new("bash-child-read");
    write(dir.path().join(".env"), "SECRET=1\n");
    dir.write_policy(&[], &[], &[".env"], &["bash"]);

    let output = run_nobody(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "bash",
            "-lc",
            r#"if cat .env; then exit 7; else echo denied-bash; fi"#,
        ],
    );

    assert_denied(&output, "denied-bash");
}
