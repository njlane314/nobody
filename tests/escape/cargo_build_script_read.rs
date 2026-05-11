#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn cargo_build_script_read_is_denied() {
    let dir = EscapeDir::new("cargo-build-script-read");
    mkdir(dir.path().join("crate/src"));
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
        Err(_) => println!("cargo:warning=denied-cargo-build-script"),
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

    let output = run_nobody(
        dir.path(),
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

    assert_denied(&output, "denied-cargo-build-script");
}
