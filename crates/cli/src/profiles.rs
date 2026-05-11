use anyhow::Result;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub struct RenderedProfile {
    pub name: &'static str,
    pub description: &'static str,
    pub policy: String,
}

pub struct ProfileSummary {
    pub name: &'static str,
    pub description: &'static str,
}

struct Profile {
    name: &'static str,
    aliases: &'static [&'static str],
    description: &'static str,
    include_safe_toplevel_read: bool,
    read_candidates: &'static [&'static str],
    write_candidates: &'static [&'static str],
    net_allow: &'static [&'static str],
    net_deny: &'static [&'static str],
    process_allow: &'static [&'static str],
    process_deny: &'static [&'static str],
    process_rules: &'static [ProcessRule],
    env_allow_extra: &'static [&'static str],
}

struct ProcessRule {
    program: &'static str,
    allow_args: &'static [&'static str],
    deny_args: &'static [&'static str],
}

const SECRET_DENY: &[&str] = &[
    ".env",
    ".env.*",
    "~/.ssh",
    "~/.aws",
    "~/.config/gcloud",
    "~/.docker/config.json",
];

const BASE_ENV_ALLOW: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "LANG", "TERM", "SHELL"];

const BASE_ENV_DENY: &[&str] = &[
    "*TOKEN*",
    "*KEY*",
    "AWS_*",
    "DATABASE_URL",
    "KUBECONFIG",
    "DOCKER_CONFIG",
    "SSH_AUTH_SOCK",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "NPM_TOKEN",
    "PYPI_TOKEN",
];

const PROCESS_DENY: &[&str] = &["curl", "wget", "ssh", "scp", "sudo", "rm", "chmod", "chown"];

const GIT_RULE: ProcessRule = ProcessRule {
    program: "git",
    allow_args: &["status", "diff", "log", "show", "add", "commit"],
    deny_args: &[],
};

const RUST_RULES: &[ProcessRule] = &[
    ProcessRule {
        program: "cargo",
        allow_args: &["test", "check", "build", "fmt", "clippy"],
        deny_args: &[],
    },
    GIT_RULE,
];

const NODE_RULES: &[ProcessRule] = &[
    ProcessRule {
        program: "node",
        allow_args: &[],
        deny_args: &["-e"],
    },
    ProcessRule {
        program: "npm",
        allow_args: &["test", "run", "install", "ci", "exec"],
        deny_args: &[],
    },
    ProcessRule {
        program: "npx",
        allow_args: &["eslint", "prettier", "tsc", "vitest", "jest"],
        deny_args: &[],
    },
    ProcessRule {
        program: "pnpm",
        allow_args: &["test", "run", "install", "exec", "dlx"],
        deny_args: &[],
    },
    ProcessRule {
        program: "yarn",
        allow_args: &["test", "run", "install", "exec", "dlx"],
        deny_args: &[],
    },
    ProcessRule {
        program: "bun",
        allow_args: &["test", "run", "install", "x"],
        deny_args: &[],
    },
    GIT_RULE,
];

const PYTHON_RULES: &[ProcessRule] = &[
    ProcessRule {
        program: "python",
        allow_args: &["-m", "pytest"],
        deny_args: &[],
    },
    ProcessRule {
        program: "python",
        allow_args: &["-m", "pip"],
        deny_args: &[],
    },
    ProcessRule {
        program: "python",
        allow_args: &["-m", "ruff"],
        deny_args: &[],
    },
    ProcessRule {
        program: "python3",
        allow_args: &["-m", "pytest"],
        deny_args: &[],
    },
    ProcessRule {
        program: "python3",
        allow_args: &["-m", "pip"],
        deny_args: &[],
    },
    ProcessRule {
        program: "python3",
        allow_args: &["-m", "ruff"],
        deny_args: &[],
    },
    ProcessRule {
        program: "pip",
        allow_args: &["install", "list", "show", "freeze"],
        deny_args: &[],
    },
    ProcessRule {
        program: "uv",
        allow_args: &["run", "sync", "pip", "lock"],
        deny_args: &[],
    },
    GIT_RULE,
];

const READONLY_RULES: &[ProcessRule] = &[GIT_RULE];

const CI_RULES: &[ProcessRule] = &[
    ProcessRule {
        program: "cargo",
        allow_args: &["test", "check", "build", "fmt", "clippy"],
        deny_args: &[],
    },
    ProcessRule {
        program: "npm",
        allow_args: &["test", "run", "install", "ci", "exec"],
        deny_args: &[],
    },
    ProcessRule {
        program: "python",
        allow_args: &["-m", "pytest"],
        deny_args: &[],
    },
    ProcessRule {
        program: "python3",
        allow_args: &["-m", "pytest"],
        deny_args: &[],
    },
    GIT_RULE,
];

const COMMON_READ: &[&str] = &[
    "./README.md",
    "./README",
    "./LICENSE",
    "./LICENSE.md",
    "./Makefile",
    "./docs",
    "./.github",
    "./.git",
];

const RUST_READ: &[&str] = &[
    "./Cargo.toml",
    "./Cargo.lock",
    "./rust-toolchain.toml",
    "./rust-toolchain",
    "./.cargo",
    "./crates",
    "./src",
    "./tests",
    "./examples",
    "./benches",
    "./man",
];

const RUST_WRITE: &[&str] = &[
    "./Cargo.toml",
    "./Cargo.lock",
    "./crates",
    "./src",
    "./tests",
    "./examples",
    "./benches",
    "./docs",
    "./man",
    "./target",
    "./.git",
];

const NODE_READ: &[&str] = &[
    "./package.json",
    "./package-lock.json",
    "./pnpm-lock.yaml",
    "./yarn.lock",
    "./bun.lockb",
    "./tsconfig.json",
    "./src",
    "./test",
    "./tests",
    "./lib",
    "./app",
    "./pages",
    "./components",
    "./public",
];

const NODE_WRITE: &[&str] = &[
    "./package.json",
    "./package-lock.json",
    "./pnpm-lock.yaml",
    "./yarn.lock",
    "./bun.lockb",
    "./src",
    "./test",
    "./tests",
    "./lib",
    "./app",
    "./pages",
    "./components",
    "./public",
    "./node_modules",
    "./dist",
    "./build",
    "./coverage",
    "./.next",
    "./.git",
];

const PYTHON_READ: &[&str] = &[
    "./pyproject.toml",
    "./setup.py",
    "./setup.cfg",
    "./requirements.txt",
    "./requirements-dev.txt",
    "./poetry.lock",
    "./uv.lock",
    "./tox.ini",
    "./pytest.ini",
    "./src",
    "./tests",
    "./test",
    "./app",
];

const PYTHON_WRITE: &[&str] = &[
    "./pyproject.toml",
    "./setup.py",
    "./setup.cfg",
    "./requirements.txt",
    "./requirements-dev.txt",
    "./src",
    "./tests",
    "./test",
    "./app",
    "./.pytest_cache",
    "./.mypy_cache",
    "./.ruff_cache",
    "./.git",
];

const CI_READ: &[&str] = &[
    "./Cargo.toml",
    "./Cargo.lock",
    "./package.json",
    "./package-lock.json",
    "./pnpm-lock.yaml",
    "./yarn.lock",
    "./pyproject.toml",
    "./requirements.txt",
    "./requirements-dev.txt",
    "./src",
    "./crates",
    "./tests",
    "./test",
    "./app",
];

const CI_WRITE: &[&str] = &[
    "./Cargo.lock",
    "./package-lock.json",
    "./pnpm-lock.yaml",
    "./yarn.lock",
    "./uv.lock",
    "./target",
    "./node_modules",
    "./.pytest_cache",
    "./.mypy_cache",
    "./.ruff_cache",
];

const PROFILES: &[Profile] = &[
    Profile {
        name: "rust-coding-agent",
        aliases: &["rust"],
        description: "Rust coding agent with Cargo-oriented commands.",
        include_safe_toplevel_read: false,
        read_candidates: RUST_READ,
        write_candidates: RUST_WRITE,
        net_allow: &[
            "github.com:443",
            "crates.io:443",
            "static.crates.io:443",
            "index.crates.io:443",
        ],
        net_deny: &[],
        process_allow: &["cargo", "rustc", "rustfmt", "git"],
        process_deny: PROCESS_DENY,
        process_rules: RUST_RULES,
        env_allow_extra: &["CARGO_HOME", "RUSTUP_HOME", "RUST_LOG", "TMPDIR"],
    },
    Profile {
        name: "node-coding-agent",
        aliases: &["node", "javascript", "typescript"],
        description: "Node coding agent with npm/pnpm/yarn/bun commands.",
        include_safe_toplevel_read: false,
        read_candidates: NODE_READ,
        write_candidates: NODE_WRITE,
        net_allow: &["registry.npmjs.org:443", "github.com:443"],
        net_deny: &[],
        process_allow: &["node", "npm", "npx", "pnpm", "yarn", "bun", "git"],
        process_deny: PROCESS_DENY,
        process_rules: NODE_RULES,
        env_allow_extra: &["NODE_ENV", "NPM_CONFIG_CACHE", "TMPDIR"],
    },
    Profile {
        name: "python-coding-agent",
        aliases: &["python", "py"],
        description: "Python coding agent with pytest, pip, uv, and ruff commands.",
        include_safe_toplevel_read: false,
        read_candidates: PYTHON_READ,
        write_candidates: PYTHON_WRITE,
        net_allow: &[
            "pypi.org:443",
            "files.pythonhosted.org:443",
            "github.com:443",
        ],
        net_deny: &[],
        process_allow: &["python", "python3", "pytest", "pip", "uv", "ruff", "git"],
        process_deny: PROCESS_DENY,
        process_rules: PYTHON_RULES,
        env_allow_extra: &["VIRTUAL_ENV", "PIP_CACHE_DIR", "UV_CACHE_DIR", "TMPDIR"],
    },
    Profile {
        name: "readonly-review-agent",
        aliases: &["readonly", "review"],
        description: "Read-only review agent with deny-all network egress.",
        include_safe_toplevel_read: true,
        read_candidates: COMMON_READ,
        write_candidates: &[],
        net_allow: &[],
        net_deny: &["*"],
        process_allow: &[
            "git", "rg", "grep", "sed", "cat", "head", "tail", "ls", "find", "wc",
        ],
        process_deny: PROCESS_DENY,
        process_rules: READONLY_RULES,
        env_allow_extra: &["TMPDIR"],
    },
    Profile {
        name: "ci-agent",
        aliases: &["ci"],
        description: "CI-oriented agent for local test and build commands.",
        include_safe_toplevel_read: false,
        read_candidates: CI_READ,
        write_candidates: CI_WRITE,
        net_allow: &[
            "github.com:443",
            "crates.io:443",
            "static.crates.io:443",
            "index.crates.io:443",
            "registry.npmjs.org:443",
            "pypi.org:443",
            "files.pythonhosted.org:443",
        ],
        net_deny: &[],
        process_allow: &["cargo", "npm", "python", "python3", "pytest", "git", "make"],
        process_deny: PROCESS_DENY,
        process_rules: CI_RULES,
        env_allow_extra: &[
            "CARGO_HOME",
            "RUSTUP_HOME",
            "NODE_ENV",
            "NPM_CONFIG_CACHE",
            "VIRTUAL_ENV",
            "PIP_CACHE_DIR",
            "UV_CACHE_DIR",
            "TMPDIR",
        ],
    },
];

pub fn summaries() -> Vec<ProfileSummary> {
    PROFILES
        .iter()
        .map(|profile| ProfileSummary {
            name: profile.name,
            description: profile.description,
        })
        .collect()
}

pub fn detect(root: &Path) -> &'static str {
    if root.join("Cargo.toml").exists() {
        "rust-coding-agent"
    } else if root.join("package.json").exists() {
        "node-coding-agent"
    } else if root.join("pyproject.toml").exists()
        || root.join("setup.py").exists()
        || root.join("requirements.txt").exists()
    {
        "python-coding-agent"
    } else {
        "readonly-review-agent"
    }
}

pub fn render(name: &str, root: &Path) -> Result<RenderedProfile> {
    let profile = find_profile(name)?;
    let mut read = existing_candidates(root, COMMON_READ);
    read.extend(existing_candidates(root, profile.read_candidates));
    if profile.include_safe_toplevel_read {
        read.extend(safe_toplevel_read(root));
    }
    let write = existing_candidates(root, profile.write_candidates);
    read.extend(write.iter().cloned());
    let read = dedup(read);
    let write = dedup(write);
    let env_allow = dedup(
        BASE_ENV_ALLOW
            .iter()
            .chain(profile.env_allow_extra.iter())
            .map(|value| (*value).to_owned())
            .collect(),
    );

    Ok(RenderedProfile {
        name: profile.name,
        description: profile.description,
        policy: render_policy(profile, &read, &write, &env_allow),
    })
}

fn find_profile(name: &str) -> Result<&'static Profile> {
    PROFILES
        .iter()
        .find(|profile| profile.name == name || profile.aliases.iter().any(|alias| *alias == name))
        .ok_or_else(|| {
            let names = PROFILES
                .iter()
                .map(|profile| profile.name)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!("unknown profile {name:?}; available profiles: {names}")
        })
}

fn render_policy(
    profile: &Profile,
    read: &[String],
    write: &[String],
    env_allow: &[String],
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "# Generated by nobody init --profile {}.",
        profile.name
    );
    let _ = writeln!(&mut out, "# Review grants before running an agent.");
    out.push('\n');
    out.push_str("[agent]\n");
    push_kv(&mut out, "name", profile.name);
    push_kv(&mut out, "kind", "local-cli");
    push_kv(&mut out, "description", profile.description);
    out.push('\n');
    out.push_str("[task]\n");
    push_kv(&mut out, "repo", ".");
    out.push('\n');
    out.push_str("[fs]\n");
    push_list(&mut out, "read", read);
    push_list(&mut out, "write", write);
    push_list_str(&mut out, "deny", SECRET_DENY);
    out.push('\n');
    out.push_str("[net]\n");
    push_kv(&mut out, "mode", "deny-by-default");
    push_list_str(&mut out, "allow", profile.net_allow);
    push_list_str(&mut out, "deny", profile.net_deny);
    out.push('\n');
    out.push_str("[process]\n");
    push_list_str(&mut out, "allow", profile.process_allow);
    push_list_str(&mut out, "deny", profile.process_deny);
    for rule in profile.process_rules {
        out.push('\n');
        out.push_str("[[process.rule]]\n");
        push_kv(&mut out, "program", rule.program);
        if !rule.allow_args.is_empty() {
            push_list_str(&mut out, "allow_args", rule.allow_args);
        }
        if !rule.deny_args.is_empty() {
            push_list_str(&mut out, "deny_args", rule.deny_args);
        }
    }
    out.push('\n');
    out.push_str("[env]\n");
    out.push_str("clear = true\n");
    push_list(&mut out, "allow", env_allow);
    push_list_str(&mut out, "deny", BASE_ENV_DENY);
    out.push('\n');
    out.push_str("[trace]\n");
    push_kv(&mut out, "path", ".nobody/runs/latest.jsonl");
    push_list_str(&mut out, "redact", &["*TOKEN*", "*KEY*", "Authorization"]);
    out
}

fn push_kv(out: &mut String, key: &str, value: &str) {
    let _ = writeln!(out, "{key} = {}", toml_quote(value));
}

fn push_list(out: &mut String, key: &str, values: &[String]) {
    let rendered = values
        .iter()
        .map(|value| toml_quote(value))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "{key} = [{rendered}]");
}

fn push_list_str(out: &mut String, key: &str, values: &[&str]) {
    let rendered = values
        .iter()
        .map(|value| toml_quote(value))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "{key} = [{rendered}]");
}

fn existing_candidates(root: &Path, candidates: &[&str]) -> Vec<String> {
    candidates
        .iter()
        .filter(|candidate| !candidate.is_empty())
        .filter(|candidate| root.join(strip_dot_slash(candidate)).exists())
        .map(|candidate| normalize_grant(candidate))
        .collect()
}

fn safe_toplevel_read(root: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut values = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| !exclude_safe_toplevel(name))
        .map(|name| normalize_grant(&name))
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn exclude_safe_toplevel(name: &str) -> bool {
    name == "nobody.toml"
        || name == ".nobody"
        || name == ".env"
        || name.starts_with(".env.")
        || matches!(
            name,
            ".ssh"
                | ".aws"
                | ".config"
                | ".docker"
                | "target"
                | "node_modules"
                | ".venv"
                | "venv"
                | ".pytest_cache"
                | ".mypy_cache"
                | ".ruff_cache"
                | ".next"
                | "dist"
                | "build"
                | "coverage"
        )
}

fn normalize_grant(value: &str) -> String {
    let trimmed = value.trim_end_matches('/');
    if trimmed.starts_with("./") {
        trimmed.to_owned()
    } else {
        format!("./{trimmed}")
    }
}

fn strip_dot_slash(value: &str) -> &str {
    value.strip_prefix("./").unwrap_or(value)
}

fn dedup(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn toml_quote(value: &str) -> String {
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(&mut quoted, "\\u{:04X}", ch as u32);
            }
            ch => quoted.push(ch),
        }
    }
    quoted.push('"');
    quoted
}
