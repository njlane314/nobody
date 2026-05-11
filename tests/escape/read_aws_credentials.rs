#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn read_aws_credentials_is_denied() {
    let dir = EscapeDir::new("read-aws-credentials");
    let home = dir.path().join("home");
    mkdir(home.join(".aws"));
    write(
        home.join(".aws/credentials"),
        "[default]\naws_secret_access_key=secret\n",
    );
    dir.write_policy(&[], &[], &["~/.aws"], &["sh"]);

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
            r#"if cat ~/.aws/credentials >/dev/null 2>&1; then exit 7; else echo denied-aws; fi"#,
        ],
    );

    assert_denied(&output, "denied-aws");
}
