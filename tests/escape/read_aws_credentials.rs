#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::common::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn read_aws_credentials_is_denied() {
    let dir = EscapeDir::new("read-aws-credentials");
    let home = dir.path().join("home");
    mkdir(home.join(".aws"));
    write(
        home.join(".aws/credentials"),
        "[default]\naws_secret_access_key=secret\n",
    );
    dir.write_policy_with_process_rules(
        &[],
        &[],
        &["~/.aws"],
        &["sh"],
        r#"
[[process.rule]]
program = "sh"
allow_args = ["-c"]
"#,
    );

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
            r#"if cat ~/.aws/credentials; then exit 7; else echo denied-aws; fi"#,
        ],
    );

    assert_denied(&output, "denied-aws");
}
