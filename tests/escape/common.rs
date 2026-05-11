#![allow(dead_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct EscapeDir {
    path: PathBuf,
}

impl EscapeDir {
    pub fn new(name: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nobody-escape-{name}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_policy(
        &self,
        read: &[&str],
        write: &[&str],
        deny: &[&str],
        process_allow: &[&str],
    ) {
        self.write_policy_with_process_rules(read, write, deny, process_allow, "");
    }

    pub fn write_policy_with_process_rules(
        &self,
        read: &[&str],
        write: &[&str],
        deny: &[&str],
        process_allow: &[&str],
        process_rules: &str,
    ) {
        self.write_policy_with_network_and_process_rules(
            read,
            write,
            deny,
            process_allow,
            process_rules,
            "deny-by-default",
            &[],
            &[],
        );
    }

    pub fn write_policy_with_network_and_process_rules(
        &self,
        read: &[&str],
        write: &[&str],
        deny: &[&str],
        process_allow: &[&str],
        process_rules: &str,
        net_mode: &str,
        net_allow: &[&str],
        net_deny: &[&str],
    ) {
        fs::write(
            self.path.join("nobody.toml"),
            format!(
                r#"
[fs]
read = [{}]
write = [{}]
deny = [{}]

[net]
mode = {net_mode:?}
allow = [{}]
deny = [{}]

[process]
allow = [{}]
deny = []
{}

[env]
clear = true
allow = ["PATH", "HOME", "USER", "LOGNAME", "LANG", "TERM", "SHELL", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR"]
deny = ["*TOKEN*", "*KEY*", "AWS_*", "DATABASE_URL", "KUBECONFIG", "DOCKER_CONFIG", "SSH_AUTH_SOCK"]

[trace]
path = ".nobody/runs/latest.jsonl"
redact = ["*TOKEN*", "*KEY*", "Authorization"]
"#,
                quoted(read),
                quoted(write),
                quoted(deny),
                quoted(net_allow),
                quoted(net_deny),
                quoted(process_allow),
                process_rules
            ),
        )
        .unwrap();
    }

    pub fn trace(&self) -> String {
        fs::read_to_string(self.path.join(".nobody/runs/latest.jsonl")).unwrap()
    }
}

impl Drop for EscapeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn nobody() -> &'static str {
    env!("CARGO_BIN_EXE_nobody")
}

pub fn run_nobody(dir: &Path, args: &[&str]) -> Output {
    Command::new(nobody())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

pub fn run_nobody_with_home(dir: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(nobody())
        .current_dir(dir)
        .env("HOME", home)
        .args(args)
        .output()
        .unwrap()
}

pub fn run_nobody_with_env(dir: &Path, envs: &[(&str, &Path)], args: &[&str]) -> Output {
    let mut command = Command::new(nobody());
    command.current_dir(dir);
    for (name, value) in envs {
        command.env(name, value);
    }
    command.args(args).output().unwrap()
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn assert_denied(output: &Output, marker: &str) {
    assert!(
        output.status.success(),
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout(output),
        stderr(output)
    );
    assert!(
        stdout(output).contains(marker),
        "missing marker {marker:?}\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

pub fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

pub fn command_path(program: &str) -> String {
    #[cfg(target_os = "macos")]
    if program == "python3" {
        if let Ok(output) = Command::new("xcrun").args(["-f", "python3"]).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if !path.is_empty() {
                    return path;
                }
            }
        }
    }

    program.into()
}

pub fn mkdir(path: impl AsRef<Path>) {
    fs::create_dir_all(path).unwrap();
}

pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).unwrap();
}

#[cfg(unix)]
pub fn symlink_file(source: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
    std::os::unix::fs::symlink(source, link)
}

fn quoted(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("{value:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}
