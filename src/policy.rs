use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub fs: FsPolicy,
    pub net: NetPolicy,
    pub shell: ShellPolicy,
    pub trace: TracePolicy,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct FsPolicy {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NetPolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ShellPolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TracePolicy {
    pub path: Option<PathBuf>,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path.display()))?;

        let policy = toml::from_str(&raw)
            .with_context(|| format!("invalid TOML policy: {}", path.display()))?;

        Ok(policy)
    }

    pub fn trace_path(&self) -> PathBuf {
        self.trace
            .path
            .clone()
            .unwrap_or_else(|| PathBuf::from(".nobody/runs/latest.jsonl"))
    }

    pub fn command_allowed(&self, program: &str) -> bool {
        let basename = program.rsplit('/').next().unwrap_or(program);

        let denied = self
            .shell
            .deny
            .iter()
            .any(|cmd| cmd == program || cmd == basename);

        if denied {
            return false;
        }

        if self.shell.allow.is_empty() {
            return true;
        }

        self.shell
            .allow
            .iter()
            .any(|cmd| cmd == program || cmd == basename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy_toml() {
        let raw = r#"
            [fs]
            read = ["./"]
            write = ["./src", "./tests"]
            deny = [".env", "~/.ssh", "~/.aws"]

            [net]
            allow = ["github.com", "api.anthropic.com"]
            deny = ["*"]

            [shell]
            allow = ["echo", "git", "cargo", "rustc"]
            deny = ["rm", "curl", "scp", "ssh"]

            [trace]
            path = ".nobody/runs/latest.jsonl"
        "#;

        let policy: Policy = toml::from_str(raw).unwrap();

        assert_eq!(policy.fs.read, vec!["./"]);
        assert_eq!(policy.fs.write, vec!["./src", "./tests"]);
        assert_eq!(policy.fs.deny, vec![".env", "~/.ssh", "~/.aws"]);
        assert_eq!(policy.net.allow, vec!["github.com", "api.anthropic.com"]);
        assert_eq!(policy.net.deny, vec!["*"]);
        assert_eq!(policy.shell.allow, vec!["echo", "git", "cargo", "rustc"]);
        assert_eq!(policy.shell.deny, vec!["rm", "curl", "scp", "ssh"]);
        assert_eq!(
            policy.trace_path(),
            PathBuf::from(".nobody/runs/latest.jsonl")
        );
    }

    #[test]
    fn denies_explicitly_denied_command() {
        let policy = Policy {
            shell: ShellPolicy {
                allow: vec!["echo".into()],
                deny: vec!["rm".into()],
            },
            ..Default::default()
        };

        assert!(!policy.command_allowed("rm"));
    }

    #[test]
    fn allows_explicitly_allowed_command() {
        let policy = Policy {
            shell: ShellPolicy {
                allow: vec!["echo".into()],
                deny: vec![],
            },
            ..Default::default()
        };

        assert!(policy.command_allowed("echo"));
    }

    #[test]
    fn denies_command_not_in_allowlist() {
        let policy = Policy {
            shell: ShellPolicy {
                allow: vec!["echo".into()],
                deny: vec![],
            },
            ..Default::default()
        };

        assert!(!policy.command_allowed("curl"));
    }

    #[test]
    fn matches_basename_for_absolute_paths() {
        let policy = Policy {
            shell: ShellPolicy {
                allow: vec!["git".into()],
                deny: vec![],
            },
            ..Default::default()
        };

        assert!(policy.command_allowed("/usr/bin/git"));
    }
}
