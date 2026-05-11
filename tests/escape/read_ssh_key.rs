#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn read_ssh_key_is_denied() {
    let dir = EscapeDir::new("read-ssh-key");
    let home = dir.path().join("home");
    mkdir(home.join(".ssh"));
    write(home.join(".ssh/id_rsa"), "private-key\n");
    dir.write_policy(&[], &[], &["~/.ssh"], &["sh"]);

    let output = run_nobody_with_home(
        dir.path(),
        &home,
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "sh",
            "-c",
            r#"if cat ~/.ssh/id_rsa; then exit 7; else echo denied-ssh; fi"#,
        ],
    );

    assert_denied(&output, "denied-ssh");
}
