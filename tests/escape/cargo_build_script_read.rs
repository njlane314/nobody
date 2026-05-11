#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn cargo_build_script_read_is_denied() {
    let dir = EscapeDir::new("cargo-build-script-read");
    mkdir(dir.path().join("crate/src"));
    mkdir(dir.path().join("crate/target/tmp"));
    write(dir.path().join(".env"), "SECRET=1\n");
    write(
        dir.path().join("crate/Cargo.toml"),
        r#"[package]
name = "escape-fixture"
version = "0.1.0"
edition = "2021"
build = "build.rs"
"#,
    );
    write(dir.path().join("crate/src/lib.rs"), "pub fn fixture() {}\n");
    write(
        dir.path().join("crate/build.rs"),
        r#"fn main() {
    match std::fs::read_to_string("../.env") {
        Ok(_) => std::process::exit(7),
        Err(_) => std::fs::write("target/denied-cargo-build-script", "ok").unwrap(),
    }
}
"#,
    );

    let mut read = vec!["./crate"];
    if let Some(home) = std::env::var_os("HOME") {
        let home = std::path::PathBuf::from(home);
        if home.join(".cargo").exists() {
            read.push("~/.cargo");
        }
        if home.join(".rustup").exists() {
            read.push("~/.rustup");
        }
    }

    dir.write_policy(&read, &["./crate"], &[".env"], &["cargo"]);

    let tmpdir = dir.path().join("crate/target/tmp");
    let output = run_nobody_with_env(
        dir.path(),
        &[("TMPDIR", tmpdir.as_path())],
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "cargo",
            "build",
            "--manifest-path",
            "crate/Cargo.toml",
            "--quiet",
        ],
    );

    assert!(
        output.status.success(),
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout(&output),
        stderr(&output)
    );
    assert!(
        dir.path()
            .join("crate/target/denied-cargo-build-script")
            .exists(),
        "build script did not record denied read\nstdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
}
