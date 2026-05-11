use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub agent: AgentPolicy,
    pub task: TaskPolicy,
    pub fs: FsPolicy,
    pub net: NetPolicy,
    pub process: ProcessPolicy,
    pub env: EnvPolicy,
    pub approval: ApprovalPolicy,
    pub trace: TracePolicy,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AgentPolicy {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TaskPolicy {
    pub id: Option<String>,
    pub repo: Option<PathBuf>,
    pub max_duration: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct FsPolicy {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NetPolicy {
    pub mode: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessPolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub rule: Vec<ProcessRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRule {
    pub program: String,
    #[serde(default)]
    pub allow_args: Vec<String>,
    #[serde(default)]
    pub deny_args: Vec<String>,
    #[serde(default)]
    pub decision: Option<ProcessRuleDecision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRuleDecision {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvPolicy {
    pub clear: bool,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalPolicy {
    pub require: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TracePolicy {
    pub path: Option<PathBuf>,
    pub redact: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    ExecuteProcess { program: String, argv: Vec<String> },
    ReadFile { path: PathBuf },
    WriteFile { path: PathBuf },
    ConnectNetwork { host: String, port: u16 },
    ReadEnv { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    ProcessExec,
    FsRead,
    FsWrite,
    NetConnect,
    EnvRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    Process { program: String, argv: Vec<String> },
    File { path: PathBuf },
    Network { host: String, port: u16 },
    Env { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalRequest {
    pub reason: DecisionReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow { reason: DecisionReason },
    Deny { reason: DecisionReason },
    Ask { request: ApprovalRequest },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionReason {
    pub rule_id: Option<String>,
    pub resource: Resource,
    pub action: ActionKind,
    pub matched_pattern: Option<String>,
    pub message: String,
}

pub struct PolicyEvaluator<'a> {
    policy: &'a Policy,
}

impl Default for EnvPolicy {
    fn default() -> Self {
        Self {
            clear: false,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path.display()))?;

        toml::from_str(&raw).with_context(|| format!("invalid TOML policy: {}", path.display()))
    }

    pub fn trace_path(&self) -> PathBuf {
        self.trace
            .path
            .clone()
            .unwrap_or_else(|| PathBuf::from(".nobody/runs/latest.jsonl"))
    }

    pub fn evaluator(&self) -> PolicyEvaluator<'_> {
        PolicyEvaluator { policy: self }
    }
}

impl<'a> PolicyEvaluator<'a> {
    pub fn evaluate(&self, action: Action) -> Decision {
        match action {
            Action::ExecuteProcess { program, argv } => self.evaluate_process(program, argv),
            Action::ReadFile { path } => self.evaluate_file(path, FileOperation::Read),
            Action::WriteFile { path } => self.evaluate_file(path, FileOperation::Write),
            Action::ConnectNetwork { host, port } => self.evaluate_network(host, port),
            Action::ReadEnv { name } => self.evaluate_env(name),
        }
    }

    fn evaluate_process(&self, program: String, argv: Vec<String>) -> Decision {
        let basename = program.rsplit('/').next().unwrap_or(&program);
        let resource = Resource::Process {
            program: program.clone(),
            argv: argv.clone(),
        };

        if let Some(pattern) = self
            .policy
            .process
            .deny
            .iter()
            .find(|cmd| process_name_matches(cmd, &program, basename))
        {
            return Decision::deny(DecisionReason {
                rule_id: Some("process.deny".into()),
                resource,
                action: ActionKind::ProcessExec,
                matched_pattern: Some(pattern.clone()),
                message: "process is explicitly denied".into(),
            });
        }

        let matching_rules: Vec<_> = self
            .policy
            .process
            .rule
            .iter()
            .filter(|rule| process_name_matches(&rule.program, &program, basename))
            .collect();

        if let Some((rule, pattern)) = matching_rules
            .iter()
            .filter_map(|rule| args_match(&rule.deny_args, &argv).map(|pattern| (*rule, pattern)))
            .next()
        {
            return Decision::deny(DecisionReason {
                rule_id: Some("process.rule.deny_args".into()),
                resource,
                action: ActionKind::ProcessExec,
                matched_pattern: Some(pattern),
                message: format!("process arguments matched deny rule for {}", rule.program),
            });
        }

        if let Some((rule, pattern)) = matching_rules
            .iter()
            .filter_map(|rule| args_match(&rule.allow_args, &argv).map(|pattern| (*rule, pattern)))
            .next()
        {
            let reason = DecisionReason {
                rule_id: Some("process.rule.allow_args".into()),
                resource,
                action: ActionKind::ProcessExec,
                matched_pattern: Some(pattern),
                message: format!("process arguments matched allow rule for {}", rule.program),
            };
            return process_rule_decision(
                rule.decision.unwrap_or(ProcessRuleDecision::Allow),
                reason,
            );
        }

        if let Some(rule) = matching_rules
            .iter()
            .find(|rule| !rule.allow_args.is_empty())
        {
            return Decision::deny(DecisionReason {
                rule_id: Some("process.rule.allow_args".into()),
                resource,
                action: ActionKind::ProcessExec,
                matched_pattern: Some(display_arg_rule(&rule.allow_args)),
                message: format!(
                    "process arguments did not match allow rule for {}",
                    rule.program
                ),
            });
        }

        if let Some(rule) = matching_rules.iter().find(|rule| rule.decision.is_some()) {
            let reason = DecisionReason {
                rule_id: Some("process.rule".into()),
                resource,
                action: ActionKind::ProcessExec,
                matched_pattern: Some(rule.program.clone()),
                message: format!("process matched rule for {}", rule.program),
            };
            return process_rule_decision(rule.decision.unwrap(), reason);
        }

        if let Some(pattern) = risky_process_pattern(basename, &argv) {
            return Decision::deny(DecisionReason {
                rule_id: Some("process.risky".into()),
                resource,
                action: ActionKind::ProcessExec,
                matched_pattern: Some(pattern.into()),
                message: "process arguments are risky without an explicit process.rule".into(),
            });
        }

        if self.policy.process.allow.is_empty() {
            return Decision::allow(DecisionReason {
                rule_id: None,
                resource,
                action: ActionKind::ProcessExec,
                matched_pattern: None,
                message: "process allowed because process.allow is empty".into(),
            });
        }

        if let Some(pattern) = self
            .policy
            .process
            .allow
            .iter()
            .find(|cmd| process_name_matches(cmd, &program, basename))
        {
            return Decision::allow(DecisionReason {
                rule_id: Some("process.allow".into()),
                resource,
                action: ActionKind::ProcessExec,
                matched_pattern: Some(pattern.clone()),
                message: "process matched allow list".into(),
            });
        }

        Decision::deny(DecisionReason {
            rule_id: Some("process.allow".into()),
            resource,
            action: ActionKind::ProcessExec,
            matched_pattern: None,
            message: "process did not match allow list".into(),
        })
    }

    fn evaluate_file(&self, path: PathBuf, operation: FileOperation) -> Decision {
        let path = normalize_path(&path);
        let resource = Resource::File { path: path.clone() };
        let action = match operation {
            FileOperation::Read => ActionKind::FsRead,
            FileOperation::Write => ActionKind::FsWrite,
        };

        if let Some(pattern) = self
            .policy
            .fs
            .deny
            .iter()
            .find(|pattern| path_matches(pattern, &path))
        {
            return Decision::deny(DecisionReason {
                rule_id: Some("fs.deny".into()),
                resource,
                action,
                matched_pattern: Some(pattern.clone()),
                message: "path is explicitly denied".into(),
            });
        }

        let grants = match operation {
            FileOperation::Read => &self.policy.fs.read,
            FileOperation::Write => &self.policy.fs.write,
        };

        if let Some(pattern) = grants.iter().find(|pattern| path_matches(pattern, &path)) {
            return Decision::allow(DecisionReason {
                rule_id: Some(
                    match operation {
                        FileOperation::Read => "fs.read",
                        FileOperation::Write => "fs.write",
                    }
                    .into(),
                ),
                resource,
                action,
                matched_pattern: Some(pattern.clone()),
                message: "path matched capability grant".into(),
            });
        }

        Decision::deny(DecisionReason {
            rule_id: Some(
                match operation {
                    FileOperation::Read => "fs.read",
                    FileOperation::Write => "fs.write",
                }
                .into(),
            ),
            resource,
            action,
            matched_pattern: None,
            message: "path did not match a capability grant".into(),
        })
    }

    fn evaluate_network(&self, host: String, port: u16) -> Decision {
        let resource = Resource::Network {
            host: host.clone(),
            port,
        };
        let endpoint = format!("{host}:{port}");

        if let Some(pattern) =
            self.policy.net.deny.iter().find(|pattern| {
                pattern_matches(pattern, &host) || pattern_matches(pattern, &endpoint)
            })
        {
            return Decision::deny(DecisionReason {
                rule_id: Some("net.deny".into()),
                resource,
                action: ActionKind::NetConnect,
                matched_pattern: Some(pattern.clone()),
                message: "network endpoint is explicitly denied".into(),
            });
        }

        if let Some(pattern) =
            self.policy.net.allow.iter().find(|pattern| {
                pattern_matches(pattern, &host) || pattern_matches(pattern, &endpoint)
            })
        {
            return Decision::allow(DecisionReason {
                rule_id: Some("net.allow".into()),
                resource,
                action: ActionKind::NetConnect,
                matched_pattern: Some(pattern.clone()),
                message: "network endpoint matched allow list".into(),
            });
        }

        let deny_by_default = self.policy.net.mode.as_deref().unwrap_or("deny-by-default")
            == "deny-by-default"
            || !self.policy.net.allow.is_empty();

        if deny_by_default {
            Decision::deny(DecisionReason {
                rule_id: Some("net.allow".into()),
                resource,
                action: ActionKind::NetConnect,
                matched_pattern: None,
                message: "network endpoint did not match allow list".into(),
            })
        } else {
            Decision::allow(DecisionReason {
                rule_id: None,
                resource,
                action: ActionKind::NetConnect,
                matched_pattern: None,
                message: "network endpoint allowed by default".into(),
            })
        }
    }

    fn evaluate_env(&self, name: String) -> Decision {
        let resource = Resource::Env { name: name.clone() };

        if let Some(pattern) = self
            .policy
            .env
            .deny
            .iter()
            .find(|pattern| pattern_matches(pattern, &name))
        {
            return Decision::deny(DecisionReason {
                rule_id: Some("env.deny".into()),
                resource,
                action: ActionKind::EnvRead,
                matched_pattern: Some(pattern.clone()),
                message: "environment variable is explicitly denied".into(),
            });
        }

        if !self.policy.env.clear {
            return Decision::allow(DecisionReason {
                rule_id: None,
                resource,
                action: ActionKind::EnvRead,
                matched_pattern: None,
                message: "environment is inherited unless denied".into(),
            });
        }

        if let Some(pattern) = self
            .policy
            .env
            .allow
            .iter()
            .find(|pattern| pattern_matches(pattern, &name))
        {
            return Decision::allow(DecisionReason {
                rule_id: Some("env.allow".into()),
                resource,
                action: ActionKind::EnvRead,
                matched_pattern: Some(pattern.clone()),
                message: "environment variable matched allow list".into(),
            });
        }

        Decision::deny(DecisionReason {
            rule_id: Some("env.allow".into()),
            resource,
            action: ActionKind::EnvRead,
            matched_pattern: None,
            message: "environment is clear by default and variable was not allowed".into(),
        })
    }
}

impl Decision {
    pub fn allow(reason: DecisionReason) -> Self {
        Self::Allow { reason }
    }

    pub fn deny(reason: DecisionReason) -> Self {
        Self::Deny { reason }
    }

    pub fn ask(reason: DecisionReason) -> Self {
        Self::Ask {
            request: ApprovalRequest { reason },
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    pub fn kind(&self) -> DecisionKind {
        match self {
            Self::Allow { .. } => DecisionKind::Allow,
            Self::Deny { .. } => DecisionKind::Deny,
            Self::Ask { .. } => DecisionKind::Ask,
        }
    }

    pub fn reason(&self) -> &DecisionReason {
        match self {
            Self::Allow { reason } | Self::Deny { reason } => reason,
            Self::Ask { request } => &request.reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allow,
    Deny,
    Ask,
}

impl fmt::Display for DecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy)]
enum FileOperation {
    Read,
    Write,
}

pub fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

fn path_matches(pattern: &str, path: &Path) -> bool {
    let patterns = path_match_candidates(Path::new(pattern));
    let paths = path_match_candidates(path);

    patterns.iter().any(|pattern| {
        paths
            .iter()
            .any(|path| path_match_strings(pattern.as_str(), path.as_str()))
    })
}

fn path_match_strings(pattern: &str, path: &str) -> bool {
    if pattern == "." {
        return !path.starts_with("..") && !Path::new(path).is_absolute();
    }

    pattern_matches(&pattern, &path)
        || path == pattern
        || path
            .strip_prefix(&pattern)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn path_match_candidates(path: &Path) -> Vec<String> {
    let value = path_to_match_string(path);
    let mut candidates = vec![value.clone()];

    if let Some(expanded) = expand_tilde(&value) {
        candidates.push(expanded);
    }

    if let Some(home_relative) = home_relative(&value) {
        candidates.push(home_relative);
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

fn path_to_match_string(path: &Path) -> String {
    let value = normalize_path(path).to_string_lossy().into_owned();
    if value == "/" {
        value
    } else {
        value.trim_end_matches('/').into()
    }
}

fn expand_tilde(value: &str) -> Option<String> {
    let rest = value.strip_prefix("~/")?;
    let home = std::env::var("HOME").ok()?;
    Some(path_to_match_string(&PathBuf::from(home).join(rest)))
}

fn home_relative(value: &str) -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = Path::new(value);
    let rest = path.strip_prefix(home).ok()?;
    if rest.as_os_str().is_empty() {
        Some("~".into())
    } else {
        Some(format!("~/{}", rest.to_string_lossy()))
    }
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }

    let Some(first_star) = pattern.find('*') else {
        return false;
    };

    let mut remainder = value;
    let (prefix, rest) = pattern.split_at(first_star);

    if !remainder.starts_with(prefix) {
        return false;
    }
    remainder = &remainder[prefix.len()..];

    let mut tail = &rest[1..];
    while let Some(next_star) = tail.find('*') {
        let part = &tail[..next_star];
        if !part.is_empty() {
            let Some(index) = remainder.find(part) else {
                return false;
            };
            remainder = &remainder[index + part.len()..];
        }
        tail = &tail[next_star + 1..];
    }

    tail.is_empty() || remainder.ends_with(tail)
}

fn process_name_matches(pattern: &str, program: &str, basename: &str) -> bool {
    pattern == program || pattern == basename
}

fn process_rule_decision(decision: ProcessRuleDecision, reason: DecisionReason) -> Decision {
    match decision {
        ProcessRuleDecision::Allow => Decision::allow(reason),
        ProcessRuleDecision::Deny => Decision::deny(reason),
        ProcessRuleDecision::Ask => Decision::ask(reason),
    }
}

fn args_match(patterns: &[String], argv: &[String]) -> Option<String> {
    if patterns.is_empty() {
        return None;
    }

    if arg_rule_is_prefix(patterns) {
        if argv_has_prefix(argv, patterns) {
            Some(display_arg_rule(patterns))
        } else {
            None
        }
    } else {
        let first = argv.first()?;
        patterns
            .iter()
            .find(|pattern| pattern.as_str() == first)
            .cloned()
    }
}

fn arg_rule_is_prefix(patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| pattern.starts_with('-'))
}

fn argv_has_prefix(argv: &[String], prefix: &[String]) -> bool {
    argv.len() >= prefix.len()
        && argv
            .iter()
            .zip(prefix.iter())
            .all(|(arg, expected)| arg == expected)
}

fn display_arg_rule(patterns: &[String]) -> String {
    patterns.join(" ")
}

fn risky_process_pattern(basename: &str, argv: &[String]) -> Option<&'static str> {
    let first = argv.first().map(String::as_str);

    if basename.starts_with("python") && first == Some("-c") {
        return Some("python -c");
    }

    if basename == "sh" && first == Some("-c") {
        return Some("sh -c");
    }

    if basename == "bash" && first == Some("-c") {
        return Some("bash -c");
    }

    if basename == "bash" && first == Some("-lc") {
        return Some("bash -lc");
    }

    if basename == "git"
        && argv.first().is_some_and(|arg| arg == "config")
        && argv.iter().skip(1).any(|arg| arg == "--global")
    {
        return Some("git config --global");
    }

    if basename == "git"
        && argv.first().is_some_and(|arg| arg == "config")
        && argv.iter().skip(1).any(|arg| arg == "--system")
    {
        return Some("git config --system");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy_toml() {
        let raw = r#"
            [agent]
            name = "coding-agent"

            [task]
            id = "fix-tests"
            repo = "."

            [fs]
            read = ["."]
            write = ["./src", "./tests"]
            deny = [".env", "~/.ssh", "~/.aws"]

            [net]
            mode = "deny-by-default"
            allow = ["github.com:443", "api.anthropic.com:443"]
            deny = []

            [process]
            allow = ["echo", "git", "cargo", "rustc"]
            deny = ["rm", "curl", "scp", "ssh"]

            [[process.rule]]
            program = "cargo"
            allow_args = ["test", "check", "build"]

            [[process.rule]]
            program = "python"
            allow_args = ["-m", "pytest"]

            [env]
            clear = true
            allow = ["PATH", "HOME", "USER"]
            deny = ["*TOKEN*", "*KEY*", "AWS_*"]

            [approval]
            require = ["process.unlisted"]

            [trace]
            path = ".nobody/runs/latest.jsonl"
            redact = ["*TOKEN*", "*KEY*"]
        "#;

        let policy: Policy = toml::from_str(raw).unwrap();

        assert_eq!(policy.agent.name.as_deref(), Some("coding-agent"));
        assert_eq!(policy.task.id.as_deref(), Some("fix-tests"));
        assert_eq!(policy.fs.read, vec!["."]);
        assert_eq!(policy.fs.write, vec!["./src", "./tests"]);
        assert_eq!(policy.fs.deny, vec![".env", "~/.ssh", "~/.aws"]);
        assert_eq!(
            policy.net.allow,
            vec!["github.com:443", "api.anthropic.com:443"]
        );
        assert_eq!(policy.net.mode.as_deref(), Some("deny-by-default"));
        assert_eq!(policy.net.deny, Vec::<String>::new());
        assert_eq!(policy.process.allow, vec!["echo", "git", "cargo", "rustc"]);
        assert_eq!(policy.process.deny, vec!["rm", "curl", "scp", "ssh"]);
        assert_eq!(policy.process.rule.len(), 2);
        assert_eq!(policy.process.rule[0].program, "cargo");
        assert_eq!(
            policy.process.rule[0].allow_args,
            vec!["test", "check", "build"]
        );
        assert_eq!(policy.process.rule[1].program, "python");
        assert_eq!(policy.process.rule[1].allow_args, vec!["-m", "pytest"]);
        assert_eq!(policy.env.allow, vec!["PATH", "HOME", "USER"]);
        assert_eq!(policy.approval.require, vec!["process.unlisted"]);
        assert_eq!(
            policy.trace_path(),
            PathBuf::from(".nobody/runs/latest.jsonl")
        );
    }

    #[test]
    fn denies_explicitly_denied_process() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["echo".into()],
                deny: vec!["rm".into()],
                rule: Vec::new(),
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "rm".into(),
            argv: Vec::new(),
        });

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn allows_explicitly_allowed_process() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["echo".into()],
                deny: vec![],
                rule: Vec::new(),
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "echo".into(),
            argv: Vec::new(),
        });

        assert!(decision.is_allow());
    }

    #[test]
    fn denies_process_not_in_allowlist() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["echo".into()],
                deny: vec![],
                rule: Vec::new(),
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "curl".into(),
            argv: Vec::new(),
        });

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn matches_basename_for_absolute_process_paths() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["git".into()],
                deny: vec![],
                rule: Vec::new(),
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "/usr/bin/git".into(),
            argv: Vec::new(),
        });

        assert!(decision.is_allow());
    }

    #[test]
    fn allows_process_rule_first_argument_alternatives() {
        let policy = Policy {
            process: ProcessPolicy {
                rule: vec![ProcessRule {
                    program: "cargo".into(),
                    allow_args: vec!["test".into(), "check".into(), "build".into()],
                    deny_args: Vec::new(),
                    decision: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let test = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "cargo".into(),
            argv: vec!["test".into(), "--workspace".into()],
        });
        let publish = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "cargo".into(),
            argv: vec!["publish".into()],
        });

        assert!(test.is_allow());
        assert!(matches!(publish, Decision::Deny { .. }));
        assert_eq!(
            publish.reason().rule_id.as_deref(),
            Some("process.rule.allow_args")
        );
    }

    #[test]
    fn allows_process_rule_argument_prefixes() {
        let policy = Policy {
            process: ProcessPolicy {
                rule: vec![ProcessRule {
                    program: "python".into(),
                    allow_args: vec!["-m".into(), "pytest".into()],
                    deny_args: Vec::new(),
                    decision: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let pytest = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "python".into(),
            argv: vec!["-m".into(), "pytest".into(), "tests".into()],
        });
        let command = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "python".into(),
            argv: vec!["-c".into(), "print(1)".into()],
        });

        assert!(pytest.is_allow());
        assert!(matches!(command, Decision::Deny { .. }));
    }

    #[test]
    fn denies_risky_interpreter_args_despite_legacy_allow() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["python".into(), "sh".into()],
                ..Default::default()
            },
            ..Default::default()
        };

        let python = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "python".into(),
            argv: vec!["-c".into(), "print(1)".into()],
        });
        let shell = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "sh".into(),
            argv: vec!["-c".into(), "echo ok".into()],
        });

        assert!(matches!(python, Decision::Deny { .. }));
        assert!(matches!(shell, Decision::Deny { .. }));
        assert_eq!(python.reason().rule_id.as_deref(), Some("process.risky"));
    }

    #[test]
    fn explicit_arg_rule_can_allow_risky_interpreter_args() {
        let policy = Policy {
            process: ProcessPolicy {
                rule: vec![ProcessRule {
                    program: "python".into(),
                    allow_args: vec!["-c".into(), "print(1)".into()],
                    deny_args: Vec::new(),
                    decision: None,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "python".into(),
            argv: vec!["-c".into(), "print(1)".into()],
        });

        assert!(decision.is_allow());
        assert_eq!(
            decision.reason().rule_id.as_deref(),
            Some("process.rule.allow_args")
        );
    }

    #[test]
    fn denies_dangerous_git_config_global_despite_legacy_allow() {
        let policy = Policy {
            process: ProcessPolicy {
                allow: vec!["git".into()],
                ..Default::default()
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ExecuteProcess {
            program: "git".into(),
            argv: vec![
                "config".into(),
                "--global".into(),
                "credential.helper".into(),
                "store".into(),
            ],
        });

        assert!(matches!(decision, Decision::Deny { .. }));
        assert_eq!(decision.reason().rule_id.as_deref(), Some("process.risky"));
    }

    #[test]
    fn denies_env_by_pattern_before_allow() {
        let policy = Policy {
            env: EnvPolicy {
                clear: true,
                allow: vec!["PATH".into(), "GITHUB_TOKEN".into()],
                deny: vec!["*TOKEN*".into()],
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ReadEnv {
            name: "GITHUB_TOKEN".into(),
        });

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn allows_env_when_clear_and_name_allowed() {
        let policy = Policy {
            env: EnvPolicy {
                clear: true,
                allow: vec!["PATH".into()],
                deny: Vec::new(),
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ReadEnv {
            name: "PATH".into(),
        });

        assert!(decision.is_allow());
    }

    #[test]
    fn denies_file_when_path_matches_deny() {
        let policy = Policy {
            fs: FsPolicy {
                read: vec![".".into()],
                write: vec![],
                deny: vec![".env".into()],
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ReadFile {
            path: PathBuf::from(".env"),
        });

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn denies_file_after_lexical_normalization() {
        let policy = Policy {
            fs: FsPolicy {
                read: vec![".".into()],
                write: vec![],
                deny: vec![".env".into()],
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ReadFile {
            path: PathBuf::from("./src/../.env"),
        });

        assert!(matches!(decision, Decision::Deny { .. }));
        assert_eq!(
            normalize_path(Path::new("./src/../.env")),
            PathBuf::from(".env")
        );
    }

    #[test]
    fn denies_home_secret_paths_by_prefix() {
        let policy = Policy {
            fs: FsPolicy {
                read: vec![".".into()],
                write: vec![],
                deny: vec!["~/.ssh".into(), "~/.aws".into()],
            },
            ..Default::default()
        };

        let ssh = policy.evaluator().evaluate(Action::ReadFile {
            path: PathBuf::from("~/.ssh/id_rsa"),
        });
        let aws = policy.evaluator().evaluate(Action::ReadFile {
            path: PathBuf::from("~/.aws/credentials"),
        });

        assert!(matches!(ssh, Decision::Deny { .. }));
        assert!(matches!(aws, Decision::Deny { .. }));
    }

    #[test]
    fn denies_expanded_home_secret_paths_by_prefix() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };

        let policy = Policy {
            fs: FsPolicy {
                read: vec![".".into()],
                write: vec![],
                deny: vec!["~/.ssh".into()],
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ReadFile {
            path: PathBuf::from(home).join(".ssh/id_rsa"),
        });

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn matches_paths_with_or_without_dot_slash() {
        let policy = Policy {
            fs: FsPolicy {
                read: vec!["./src".into()],
                write: vec![],
                deny: Vec::new(),
            },
            ..Default::default()
        };

        let decision = policy.evaluator().evaluate(Action::ReadFile {
            path: PathBuf::from("src/lib.rs"),
        });

        assert!(decision.is_allow());
    }

    #[test]
    fn pattern_match_supports_secret_globs() {
        assert!(pattern_matches("*TOKEN*", "GITHUB_TOKEN"));
        assert!(pattern_matches("AWS_*", "AWS_SECRET_ACCESS_KEY"));
        assert!(pattern_matches("github.com:*", "github.com:443"));
        assert!(!pattern_matches("AWS_*", "GITHUB_TOKEN"));
    }
}
