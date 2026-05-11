#[cfg(target_os = "linux")]
use super::common::*;

#[cfg(target_os = "linux")]
#[test]
fn network_egress_is_denied() {
    if !command_available("python3") {
        eprintln!("skipping network_egress: python3 not found");
        return;
    }

    let dir = EscapeDir::new("network-egress");
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

    let output = run_nobody(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "python3",
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
    assert!(trace.contains(r#""backend":"landlock+netns""#), "{trace}");
    assert!(trace.contains(r#""network_enforced":true"#), "{trace}");
    assert!(trace.contains(r#""network_mode":"deny-all""#), "{trace}");
}
