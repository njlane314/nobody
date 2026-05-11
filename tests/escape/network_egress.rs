#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::common::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn network_egress_is_denied() {
    if !command_available("python3") {
        eprintln!("skipping network_egress: python3 not found");
        return;
    }
    let python = command_path("python3");

    let dir = EscapeDir::new("network-egress");
    #[cfg(target_os = "macos")]
    mkdir(dir.path().join("tmp"));

    #[cfg(target_os = "linux")]
    dir.write_policy_with_network_and_process_rules(
        &[],
        &[],
        &[],
        &["python3"],
        r#"
[[process.rule]]
program = "python3"
allow_args = ["-c"]
"#,
        "deny-by-default",
        &[],
        &["*"],
    );

    #[cfg(target_os = "macos")]
    dir.write_policy_with_network_and_process_rules(
        &["."],
        &["./tmp"],
        &[],
        &["python3"],
        r#"
[[process.rule]]
program = "python3"
allow_args = ["-c"]
"#,
        "deny-by-default",
        &[],
        &["*"],
    );

    #[cfg(target_os = "linux")]
    let output = run_nobody(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            &python,
            "-c",
            r#"import socket, sys
try:
    socket.create_connection(("1.1.1.1", 53), timeout=1.0)
except OSError:
    print("denied-network")
else:
    sys.exit(7)
"#,
        ],
    );

    #[cfg(target_os = "macos")]
    let output = run_nobody_with_env(
        dir.path(),
        &[("TMPDIR", dir.path().join("tmp").as_path())],
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            &python,
            "-c",
            r#"import socket, sys
try:
    socket.create_connection(("1.1.1.1", 53), timeout=1.0)
except OSError:
    print("denied-network")
else:
    sys.exit(7)
"#,
        ],
    );

    assert_denied(&output, "denied-network");
    let trace = dir.trace();
    #[cfg(target_os = "linux")]
    assert!(trace.contains(r#""backend":"landlock+netns""#), "{trace}");
    #[cfg(target_os = "macos")]
    assert!(
        trace.contains(r#""backend":"sandbox-exec+network""#),
        "{trace}"
    );
    assert!(trace.contains(r#""network_enforced":true"#), "{trace}");
    assert!(trace.contains(r#""network_mode":"deny-all""#), "{trace}");
}
