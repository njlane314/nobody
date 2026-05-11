use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("nobody-{name}-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_policy(&self) {
        fs::write(
            self.path.join("nobody.toml"),
            r#"
[fs]
read = []
write = []
deny = [".env", "~/.ssh", "~/.aws"]

[net]
mode = "deny-by-default"
allow = []
deny = []

[process]
allow = ["echo", "sh"]
deny = ["curl"]

[[process.rule]]
program = "sh"
allow_args = ["-c"]

[env]
clear = true
allow = ["PATH", "HOME", "USER"]
deny = ["*TOKEN*", "*KEY*", "AWS_*", "SSH_AUTH_SOCK"]

[trace]
path = ".nobody/runs/latest.jsonl"
redact = ["*TOKEN*", "*KEY*", "Authorization"]
"#,
        )
        .unwrap();
    }

    fn write_process_rule_policy(&self) {
        fs::write(
            self.path.join("nobody.toml"),
            r#"
[fs]
read = []
write = []
deny = []

[net]
mode = "deny-by-default"
allow = []
deny = []

[process]
allow = []
deny = []

[[process.rule]]
program = "cargo"
allow_args = ["test", "check", "build"]

[[process.rule]]
program = "python"
allow_args = ["-m", "pytest"]

[[process.rule]]
program = "git"
allow_args = ["status", "diff", "log", "show", "add", "commit"]

[env]
clear = true
allow = ["PATH", "HOME", "USER"]
deny = ["*TOKEN*", "*KEY*"]

[trace]
path = ".nobody/runs/latest.jsonl"
redact = ["*TOKEN*", "*KEY*"]
"#,
        )
        .unwrap();
    }

    fn write_diagnostic_policy(&self) {
        fs::write(
            self.path.join("nobody.toml"),
            r#"
[fs]
read = ["."]
write = []
deny = [".env"]

[net]
mode = "deny-by-default"
allow = []
deny = []

[process]
allow = ["python", "cargo"]
deny = ["curl"]

[env]
clear = true
allow = ["PATH"]
deny = ["*TOKEN*"]

[trace]
path = ".nobody/runs/latest.jsonl"
"#,
        )
        .unwrap();
    }

    fn write_mcp_policy(&self) {
        fs::write(
            self.path.join("nobody.toml"),
            r#"
[fs]
read = []
write = []
deny = []

[net]
mode = "deny-by-default"
allow = []
deny = []

[process]
allow = ["cat"]
deny = []

[env]
clear = true
allow = ["PATH", "HOME", "USER"]
deny = ["*TOKEN*", "*KEY*"]

[mcp.github]
allow_tools = ["issue.read", "pull_request.read", "repo.file.read"]
deny_tools = ["pull_request.merge", "repo.file.write"]

[[mcp.github.rule]]
tool = "pull_request.comment"
decision = "ask"

[trace]
path = ".nobody/runs/latest.jsonl"
redact = ["*TOKEN*", "*KEY*"]
"#,
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    fn write_unenforceable_filesystem_policy(&self) {
        fs::write(
            self.path.join("nobody.toml"),
            r#"
[fs]
read = ["."]
write = []
deny = [".env"]

[net]
mode = "deny-by-default"
allow = []
deny = []

[process]
allow = ["echo"]
deny = []

[env]
clear = true
allow = ["PATH", "HOME", "USER"]
deny = ["*TOKEN*", "*KEY*"]

[trace]
path = ".nobody/runs/latest.jsonl"
"#,
        )
        .unwrap();
        fs::write(self.path.join(".env"), "SECRET").unwrap();
    }

    fn trace(&self) -> String {
        fs::read_to_string(self.path.join(".nobody/runs/latest.jsonl")).unwrap()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn nobody() -> &'static str {
    env!("CARGO_BIN_EXE_nobody")
}

fn run_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(nobody())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn run_in_with_stdin(dir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(nobody())
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    child.wait_with_output().unwrap()
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn trace_events(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn init_lists_builtin_profiles() {
    let dir = TestDir::new("init-list-profiles");

    let output = run_in(dir.path(), &["init", "--list-profiles"]);

    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("rust-coding-agent"), "{out}");
    assert!(out.contains("node-coding-agent"), "{out}");
    assert!(out.contains("python-coding-agent"), "{out}");
    assert!(out.contains("readonly-review-agent"), "{out}");
    assert!(out.contains("ci-agent"), "{out}");
}

#[test]
fn init_detects_rust_profile_and_refuses_overwrite() {
    let dir = TestDir::new("init-rust");
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\n",
    )
    .unwrap();
    fs::write(dir.path().join("README.md"), "demo\n").unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::create_dir_all(dir.path().join("tests")).unwrap();

    let output = run_in(dir.path(), &["init"]);

    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("profile: rust-coding-agent"), "{out}");

    let policy = read(dir.path().join("nobody.toml"));
    assert!(policy.contains("name = \"rust-coding-agent\""), "{policy}");
    assert!(policy.contains("\"./Cargo.toml\""), "{policy}");
    assert!(policy.contains("\"./src\""), "{policy}");
    assert!(policy.contains("\"./tests\""), "{policy}");
    assert!(!policy.contains("\"./examples\""), "{policy}");

    let check = run_in(dir.path(), &["policy", "check", "nobody.toml"]);
    assert!(check.status.success(), "{}", stderr(&check));

    let overwrite = run_in(dir.path(), &["init"]);
    assert!(!overwrite.status.success(), "{}", stdout(&overwrite));
    assert!(stderr(&overwrite).contains("refusing to overwrite"));

    let forced = run_in(dir.path(), &["init", "--force"]);
    assert!(forced.status.success(), "{}", stderr(&forced));
}

#[test]
fn init_writes_readonly_profile_with_deny_all_network() {
    let dir = TestDir::new("init-readonly");
    fs::write(dir.path().join("README.md"), "demo\n").unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();

    let output = run_in(
        dir.path(),
        &[
            "init",
            "--profile",
            "readonly-review-agent",
            "--output",
            "review.toml",
        ],
    );

    assert!(output.status.success(), "{}", stderr(&output));
    let policy = read(dir.path().join("review.toml"));
    assert!(
        policy.contains("name = \"readonly-review-agent\""),
        "{policy}"
    );
    assert!(policy.contains("write = []"), "{policy}");
    assert!(policy.contains("deny = [\"*\"]"), "{policy}");
    assert!(policy.contains("\"./README.md\""), "{policy}");
    assert!(policy.contains("\"./src\""), "{policy}");

    let check = run_in(dir.path(), &["policy", "check", "review.toml"]);
    assert!(check.status.success(), "{}", stderr(&check));

    let net = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "review.toml",
            "--",
            "net.connect",
            "github.com:443",
        ],
    );
    assert!(net.status.success(), "{}", stderr(&net));
    assert!(stdout(&net).contains("DENY net.connect github.com:443"));
}

#[test]
fn init_rejects_unknown_profile() {
    let dir = TestDir::new("init-unknown");

    let output = run_in(dir.path(), &["init", "--profile", "nope"]);

    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(stderr(&output).contains("unknown profile"));
}

#[test]
fn doctor_reports_runtime_status() {
    let dir = TestDir::new("doctor");
    dir.write_policy();

    let output = run_in(dir.path(), &["doctor", "--policy", "nobody.toml"]);

    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("nobody doctor"), "{out}");
    assert!(out.contains("os:"), "{out}");
    assert!(out.contains("policy: nobody.toml ok"), "{out}");
    assert!(out.contains("trace: .nobody/runs/latest.jsonl"), "{out}");
    assert!(out.contains("runtime:"), "{out}");
    assert!(out.contains("process allow:"), "{out}");
    assert!(out.contains("environment clear: true"), "{out}");
    assert!(out.contains("mcp scope: proxy-only"), "{out}");
    assert!(out.contains("sandbox:"), "{out}");
    assert!(out.contains("backend:"), "{out}");
    assert!(out.contains("filesystem:"), "{out}");
    assert!(out.contains("network:"), "{out}");
    assert!(out.contains("limits:"), "{out}");
    assert!(out.contains("network host allowlists: diagnostic"), "{out}");
    assert!(out.contains("mcp: proxy-only"), "{out}");
    assert!(out.contains("status:"), "{out}");
}

#[test]
fn policy_simulate_mcp_tool_returns_expected_decisions() {
    let dir = TestDir::new("simulate-mcp");
    dir.write_mcp_policy();

    let allow = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "mcp.tool",
            "github",
            "issue.read",
        ],
    );
    assert!(allow.status.success(), "{}", stderr(&allow));
    assert!(stdout(&allow).contains("ALLOW mcp.tool github/issue.read"));

    let deny = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "mcp.tool",
            "github",
            "pull_request.merge",
        ],
    );
    assert!(deny.status.success(), "{}", stderr(&deny));
    assert!(stdout(&deny).contains("DENY mcp.tool github/pull_request.merge"));

    let ask = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "mcp.tool",
            "github",
            "pull_request.comment",
        ],
    );
    assert!(ask.status.success(), "{}", stderr(&ask));
    assert!(stdout(&ask).contains("ASK mcp.tool github/pull_request.comment"));
}

#[test]
fn mcp_proxy_allows_and_traces_allowed_tool_call() {
    let dir = TestDir::new("mcp-proxy-allow");
    dir.write_mcp_policy();
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue.read","arguments":{"number":1}}}"#;

    let output = run_in_with_stdin(
        dir.path(),
        &[
            "mcp",
            "proxy",
            "github",
            "--policy",
            "nobody.toml",
            "--",
            "cat",
        ],
        &format!("{request}\n"),
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains(request));
    let trace = dir.trace();
    assert!(trace.contains("mcp.tool.allow"), "{trace}");
    assert!(trace.contains(r#""tool":"issue.read""#), "{trace}");
    assert!(!trace.contains("number"), "{trace}");
}

#[test]
fn mcp_proxy_denies_tool_call_without_forwarding() {
    let dir = TestDir::new("mcp-proxy-deny");
    dir.write_mcp_policy();
    let request = r#"{"jsonrpc":"2.0","id":"deny-1","method":"tools/call","params":{"name":"pull_request.merge","arguments":{"secret":"do-not-trace"}}}"#;

    let output = run_in_with_stdin(
        dir.path(),
        &[
            "mcp",
            "proxy",
            "github",
            "--policy",
            "nobody.toml",
            "--",
            "cat",
        ],
        &format!("{request}\n"),
    );

    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains(r#""id":"deny-1""#), "{out}");
    assert!(out.contains("MCP tool is explicitly denied"), "{out}");
    assert!(!out.contains("do-not-trace"), "{out}");

    let trace = dir.trace();
    assert!(trace.contains("mcp.tool.deny"), "{trace}");
    assert!(trace.contains(r#""tool":"pull_request.merge""#), "{trace}");
    assert!(!trace.contains("do-not-trace"), "{trace}");
}

#[test]
fn denied_process_is_blocked_and_traced() {
    let dir = TestDir::new("denied-process");
    dir.write_policy();

    let output = run_in(
        dir.path(),
        &[
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "curl",
            "https://example.com",
        ],
    );

    assert!(!output.status.success());
    assert!(stderr(&output).contains("process denied by policy"));

    let trace = dir.trace();
    assert!(trace.contains("process.exec.deny"));
    assert!(trace.contains(r#""decision":"deny""#));
    assert!(trace.contains("run.completed"));
    assert!(trace.contains(r#""success":false"#));
    assert!(trace.contains(r#""reason":"process_denied""#));
    assert!(!trace.contains("process.started"));
}

#[cfg(target_os = "linux")]
#[test]
fn unenforceable_filesystem_policy_fails_closed_and_traces_completion() {
    let dir = TestDir::new("sandbox-prepare-failed");
    dir.write_unenforceable_filesystem_policy();

    let output = run_in(
        dir.path(),
        &["run", "--policy", "nobody.toml", "--", "echo", "hello"],
    );

    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(stderr(&output).contains("failed to prepare sandbox"));

    let trace = dir.trace();
    assert!(trace.contains("sandbox.prepare.failed"), "{trace}");
    assert!(trace.contains("run.completed"), "{trace}");
    assert!(trace.contains(r#""success":false"#), "{trace}");
    assert!(
        trace.contains(r#""reason":"sandbox_prepare_failed""#),
        "{trace}"
    );
    assert!(!trace.contains("process.started"), "{trace}");
}

#[test]
fn allowed_process_records_allow_trace_event() {
    let dir = TestDir::new("allowed-process");
    dir.write_policy();

    let output = run_in(
        dir.path(),
        &["run", "--policy", "nobody.toml", "--", "echo", "hello"],
    );

    assert!(output.status.success(), "{}", stderr(&output));

    let trace = dir.trace();
    assert!(trace.contains("process.exec.allow"));
    assert!(trace.contains(r#""decision":"allow""#));
    assert!(trace.contains("process.started"));
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn non_linux_run_warns_that_filesystem_sandbox_is_noop() {
    let dir = TestDir::new("noop-warning");
    dir.write_policy();

    let output = run_in(
        dir.path(),
        &["run", "--policy", "nobody.toml", "--", "echo", "hello"],
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("WARNING"));
    assert!(stderr(&output).contains("filesystem policy is diagnostic only"));
    assert!(dir.trace().contains("sandbox.prepared"));
    assert!(dir.trace().contains(r#""enforced":false"#));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_run_uses_sandbox_exec() {
    let dir = TestDir::new("macos-sandbox-exec");
    dir.write_policy();

    let output = run_in(
        dir.path(),
        &["run", "--policy", "nobody.toml", "--", "echo", "hello"],
    );

    assert!(output.status.success(), "{}", stderr(&output));
    let trace = dir.trace();
    assert!(trace.contains(r#""backend":"sandbox-exec""#), "{trace}");
    assert!(trace.contains(r#""filesystem_enforced":true"#), "{trace}");
    assert!(trace.contains(r#""enforced":true"#), "{trace}");
}

#[test]
fn secret_environment_is_filtered_without_tracing_values() {
    let dir = TestDir::new("env-filter");
    dir.write_policy();

    let secret = "SECRET_VALUE_SHOULD_NOT_APPEAR";
    let output = Command::new(nobody())
        .current_dir(dir.path())
        .env("GITHUB_TOKEN", secret)
        .args([
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "sh",
            "-c",
            r#"if [ -n "$GITHUB_TOKEN" ]; then echo leaked; exit 7; fi; echo clean"#,
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("clean"));

    let trace = dir.trace();
    assert!(trace.contains("env.filtered"));
    assert!(trace.contains("GITHUB_TOKEN"));
    assert!(!trace.contains(secret));
}

#[test]
fn child_process_inherits_filtered_environment() {
    let dir = TestDir::new("child-env");
    dir.write_policy();

    let output = Command::new(nobody())
        .current_dir(dir.path())
        .env("GITHUB_TOKEN", "CHILD_SECRET_VALUE_SHOULD_NOT_APPEAR")
        .args([
            "run",
            "--policy",
            "nobody.toml",
            "--",
            "sh",
            "-c",
            r#"(test -z "$GITHUB_TOKEN" && test -n "$PATH") && echo child-clean"#,
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("child-clean"));
}

#[test]
fn filesystem_denials_are_simulated_with_diagnostics() {
    let dir = TestDir::new("fs-simulate");
    dir.write_policy();

    for path in [
        ".env",
        "./src/../.env",
        "~/.ssh/id_rsa",
        "~/.aws/credentials",
    ] {
        let output = run_in(
            dir.path(),
            &["policy", "simulate", "nobody.toml", "--", "fs.read", path],
        );

        assert!(output.status.success(), "{}", stderr(&output));
        let out = stdout(&output);
        assert!(out.contains("DENY fs.read"), "{out}");
        assert!(out.contains("rule: fs.deny"), "{out}");
        assert!(out.contains("filesystem decisions are diagnostic"), "{out}");
    }
}

#[test]
fn policy_simulate_examples_return_expected_decisions() {
    let dir = TestDir::new("simulate-examples");
    dir.write_policy();

    let process = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "process.exec",
            "curl",
        ],
    );
    assert!(process.status.success(), "{}", stderr(&process));
    assert!(stdout(&process).contains("DENY process.exec curl"));

    let env = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "env.read",
            "GITHUB_TOKEN",
        ],
    );
    assert!(env.status.success(), "{}", stderr(&env));
    assert!(stdout(&env).contains("DENY env.read GITHUB_TOKEN"));

    let fs = run_in(
        dir.path(),
        &["policy", "simulate", "nobody.toml", "--", "fs.read", ".env"],
    );
    assert!(fs.status.success(), "{}", stderr(&fs));
    assert!(stdout(&fs).contains("DENY fs.read .env"));

    let net = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "net.connect",
            "github.com:443",
        ],
    );
    assert!(net.status.success(), "{}", stderr(&net));
    let net_out = stdout(&net);
    assert!(
        net_out.contains("DENY net.connect github.com:443"),
        "{net_out}"
    );
    assert!(
        net_out.contains("network host allowlists are diagnostic"),
        "{net_out}"
    );
}

#[test]
fn policy_simulate_process_rules_return_expected_decisions() {
    let dir = TestDir::new("simulate-process-rules");
    dir.write_process_rule_policy();

    let cargo_test = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "process.exec",
            "cargo",
            "test",
            "--workspace",
        ],
    );
    assert!(cargo_test.status.success(), "{}", stderr(&cargo_test));
    assert!(stdout(&cargo_test).contains("ALLOW process.exec cargo test --workspace"));
    assert!(stdout(&cargo_test).contains("rule: process.rule.allow_args"));

    let cargo_publish = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "process.exec",
            "cargo",
            "publish",
        ],
    );
    assert!(cargo_publish.status.success(), "{}", stderr(&cargo_publish));
    assert!(stdout(&cargo_publish).contains("DENY process.exec cargo publish"));

    let python_pytest = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "process.exec",
            "python",
            "-m",
            "pytest",
            "tests",
        ],
    );
    assert!(python_pytest.status.success(), "{}", stderr(&python_pytest));
    assert!(stdout(&python_pytest).contains("ALLOW process.exec python -m pytest tests"));

    let python_command = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "process.exec",
            "python",
            "-c",
            "print(1)",
        ],
    );
    assert!(
        python_command.status.success(),
        "{}",
        stderr(&python_command)
    );
    assert!(stdout(&python_command).contains("DENY process.exec python -c print(1)"));

    let git_global = run_in(
        dir.path(),
        &[
            "policy",
            "simulate",
            "nobody.toml",
            "--",
            "process.exec",
            "git",
            "config",
            "--global",
            "user.name",
            "nobody",
        ],
    );
    assert!(git_global.status.success(), "{}", stderr(&git_global));
    assert!(stdout(&git_global).contains("DENY process.exec git config --global user.name nobody"));
}

#[test]
fn policy_check_reports_shape_and_warnings() {
    let dir = TestDir::new("policy-check");
    dir.write_diagnostic_policy();

    let output = run_in(dir.path(), &["policy", "check", "nobody.toml"]);

    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("policy ok: nobody.toml"), "{out}");
    assert!(out.contains("trace: .nobody/runs/latest.jsonl"), "{out}");
    assert!(out.contains("process:"), "{out}");
    assert!(out.contains("allow: python, cargo"), "{out}");
    assert!(out.contains("filesystem:"), "{out}");
    assert!(out.contains("read: ."), "{out}");
    assert!(out.contains("network:"), "{out}");
    assert!(out.contains("mode: deny-by-default"), "{out}");
    assert!(out.contains("environment:"), "{out}");
    assert!(out.contains("clear: true"), "{out}");
    assert!(out.contains("warning[process.risky_legacy_allow]"), "{out}");
    assert!(out.contains("warning[fs.landlock_deny_carveout]"), "{out}");
    assert!(out.contains("warning[net.egress_diagnostic]"), "{out}");
}

#[test]
fn trace_explain_latest_summarizes_run_and_timeline() {
    let dir = TestDir::new("trace-explain");
    dir.write_policy();

    let run = run_in(
        dir.path(),
        &["run", "--policy", "nobody.toml", "--", "echo", "hello"],
    );
    assert!(run.status.success(), "{}", stderr(&run));

    let output = run_in(dir.path(), &["trace", "explain", "latest"]);

    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("Run run-"), "{out}");
    assert!(out.contains("Command: echo hello"), "{out}");
    assert!(out.contains("Policy: nobody.toml"), "{out}");
    assert!(out.contains("Sandbox: backend="), "{out}");
    assert!(out.contains("network_mode=diagnostic"), "{out}");
    assert!(out.contains("Duration:"), "{out}");
    assert!(out.contains("Exit: code=0 success=true"), "{out}");
    assert!(out.contains("Timeline:"), "{out}");
    assert!(
        out.contains("process.exec ALLOW echo hello rule=process.allow"),
        "{out}"
    );
    assert!(out.contains("env.filtered allowed="), "{out}");
    assert!(out.contains("sandbox.prepared backend="), "{out}");
}

#[test]
fn trace_show_latest_jsonl_returns_only_latest_run() {
    let dir = TestDir::new("trace-jsonl");
    dir.write_policy();

    let first = run_in(
        dir.path(),
        &["run", "--policy", "nobody.toml", "--", "echo", "first"],
    );
    assert!(first.status.success(), "{}", stderr(&first));

    let second = run_in(
        dir.path(),
        &["run", "--policy", "nobody.toml", "--", "echo", "second"],
    );
    assert!(second.status.success(), "{}", stderr(&second));

    let output = run_in(dir.path(), &["trace", "show", "latest", "--jsonl"]);
    assert!(output.status.success(), "{}", stderr(&output));

    let raw = stdout(&output);
    let events = trace_events(&raw);

    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|event| event["run_id"] == events[0]["run_id"])
    );
    assert!(raw.contains("second"));
    assert!(!raw.contains("first"));
}
