use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
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
    assert!(!trace.contains("process.started"));
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

#[cfg(not(target_os = "linux"))]
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
