#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn python_child_read_is_denied() {
    if !command_available("python3") {
        eprintln!("skipping python_child_read: python3 not found");
        return;
    }

    let dir = EscapeDir::new("python-child-read");
    write(dir.path().join(".env"), "SECRET=1\n");
    dir.write_policy(&[], &[], &[".env"], &["python3"]);

    let output = run_nobody(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "python3",
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
