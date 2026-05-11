#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn npm_script_read_is_denied() {
    if !command_available("npm") {
        eprintln!("skipping npm_script_read: npm not found");
        return;
    }

    let dir = EscapeDir::new("npm-script-read");
    mkdir(dir.path().join("app"));
    write(dir.path().join(".env"), "SECRET=1\n");
    write(
        dir.path().join("app/package.json"),
        r#"{"scripts":{"read-secret":"node -e \"const fs=require('fs'); try { fs.readFileSync('../.env'); process.exit(7); } catch (_) { console.log('denied-npm'); }\""}}
"#,
    );
    dir.write_policy(&["./app"], &["./app"], &[".env"], &["npm"]);

    let output = run_nobody(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "npm",
            "--prefix",
            "app",
            "run",
            "--silent",
            "read-secret",
        ],
    );

    assert_denied(&output, "denied-npm");
}
