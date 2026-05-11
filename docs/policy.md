# Policy format

`nobody` reads policy from `nobody.toml`.

The current runtime parses agent, task, filesystem, network, process,
environment, approval, and trace sections. Process policy, environment
filtering, Linux and macOS filesystem boundaries, explicit deny-all network
egress, and stdio MCP tool policy are enforced today. Host-level network
allowlists and approvals describe the intended policy surface and are parsed so
the file shape can stabilize before those enforcement backends land.

## Example

```toml
[agent]
name = "coding-agent"
kind = "local-cli"

[task]
id = "fix-tests"
repo = "."

[fs]
read = ["./Cargo.toml", "./Cargo.lock", "./Makefile", "./README.md", "./crates", "./docs"]
write = ["./Cargo.toml", "./Cargo.lock", "./README.md", "./crates", "./docs"]
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

[[process.rule]]
program = "git"
allow_args = ["status", "diff", "log", "show", "add", "commit"]

[env]
clear = true
allow = ["PATH", "HOME", "USER", "LOGNAME", "LANG", "TERM", "SHELL"]
deny = ["*TOKEN*", "*KEY*", "AWS_*", "DATABASE_URL", "SSH_AUTH_SOCK"]

[approval]
require = ["process.unlisted"]

[mcp.github]
allow_tools = ["issue.read", "pull_request.read", "repo.file.read"]
deny_tools = ["pull_request.merge", "repo.file.write"]

[[mcp.github.rule]]
tool = "pull_request.comment"
decision = "ask"

[trace]
path = ".nobody/runs/latest.jsonl"
redact = ["*TOKEN*", "*KEY*", "Authorization"]
```

## Decisions

Policy checks return a structured decision:

- `allow`: the action may continue.
- `deny`: the action is blocked.
- `ask`: reserved for approval gates.

Each decision carries the resource, action, matched rule, matched pattern, and
reason. The CLI records process decisions in the trace before spawning the
command.

Simulate a decision without running a command:

```sh
nobody policy simulate nobody.toml -- process.exec curl
nobody policy simulate nobody.toml -- env.read GITHUB_TOKEN
nobody policy simulate nobody.toml -- fs.read .env
nobody policy simulate nobody.toml -- mcp.tool github issue.read
```

Check a policy file and summarize the declared shape:

```sh
nobody policy check nobody.toml
```

`policy check` reports the trace path, process allow/deny lists, process rules,
filesystem grants, network mode, environment filtering, and warnings. Current
warnings flag risky legacy process allows such as `python` or `sh` without a
matching `[[process.rule]]`, filesystem deny carve-outs that Linux Landlock
cannot enforce under granted path trees, and network policy shapes that are
diagnostic until a later egress proxy exists.

Generate a starter policy with a built-in profile:

```sh
nobody init --profile rust-coding-agent
```

Profiles are plain TOML templates. They include only filesystem paths that
exist in the current directory so generated policies do not rely on impossible
Landlock deny carve-outs.

## Processes

`process.deny` always wins. If `process.allow` is empty, processes are allowed
unless denied. If `process.allow` is non-empty, a process must appear in that
list and must not appear in `process.deny`.

Commands match either the exact program string or its basename. For example,
`git` matches both `git` and `/usr/bin/git`.

`[[process.rule]]` adds argument-aware rules for a program. A rule with
`allow_args` constrains matching programs to conservative argv forms. If the
first `allow_args` value starts with `-`, the whole array is treated as an argv
prefix, so `["-m", "pytest"]` allows `python -m pytest ...`. Otherwise the
array is treated as allowed first arguments, so `["test", "check", "build"]`
allows `cargo test`, `cargo check`, and `cargo build`.

`deny_args` uses the same matching rules and wins over `allow_args`. A rule may
also set `decision = "deny"` or `decision = "ask"`, although ask decisions fail
closed until approval gates are implemented.

Risky interpreter and credential-changing forms are denied unless an explicit
argument rule allows them. Today that includes `python -c`, `sh -c`,
`bash -c`, `bash -lc`, and `git config --global` or `git config --system`.

```toml
[[process.rule]]
program = "cargo"
allow_args = ["test", "check", "build"]

[[process.rule]]
program = "python"
allow_args = ["-m", "pytest"]

[[process.rule]]
program = "git"
allow_args = ["status", "diff", "log", "show", "add", "commit"]
```

## Filesystem

Filesystem policy is parsed and evaluated by the policy crate. It is enforced
on Linux with Landlock and on macOS with a Seatbelt sandbox profile. Other
hosts remain diagnostic and the runtime prints a warning before spawning the
command.

Filesystem simulation normalizes paths lexically before matching rules. For
example, `./src/../.env` is evaluated as `.env`. It also compares `~/...`
patterns against the current `HOME` path, so `~/.ssh` still matches after a
shell expands it to an absolute path. Explicit `fs.deny` rules win over read
and write grants.

Landlock is additive: it grants access to allowed path trees but cannot express
an explicit deny beneath an already-granted tree. A policy such as `read = ["."]`
with `deny = [".env"]` is useful for simulation, but `nobody run` fails closed
on Linux instead of pretending that carve-out is enforceable. Grant narrower
paths when you need real filesystem enforcement.

macOS Seatbelt profiles can express deny carve-outs below granted paths, so the
same `read = ["."]` with `deny = [".env"]` shape is enforceable on macOS.

```sh
nobody policy simulate nobody.toml -- fs.read .env
```

```text
DENY fs.read .env
rule: fs.deny
matched: .env
reason: path is explicitly denied
note: filesystem decisions are diagnostic; run enforcement depends on the active sandbox backend
```

## Environment

When `env.clear = true`, the runtime clears inherited environment variables and
re-adds only variables that match `env.allow` and do not match `env.deny`.

When `env.clear = false`, variables are inherited unless they match `env.deny`.

Trace events include variable names and counts, but not values.

## Network

Network policy is parsed and can be evaluated by the policy crate.

On Linux, `deny = ["*"]` requests a fresh network namespace before the child
execs. That namespace starts without host routes, so outbound egress is denied
for the process and its descendants. On macOS, `deny = ["*"]` denies network
operations in the Seatbelt profile. The trace records both as
`network_mode="deny-all"` and `network_enforced=true`.

Host allowlists are not raw-socket enforcement yet. With
`mode = "deny-by-default"`, endpoints must match `net.allow` for policy
simulation unless they match an explicit `net.deny` rule, but runtime
allowlist enforcement remains diagnostic until a later proxy or namespace
bridge exists.

## MCP

MCP policy is declared under `[mcp.<server>]`.

```toml
[mcp.github]
allow_tools = ["issue.read", "pull_request.read", "repo.file.read"]
deny_tools = ["pull_request.merge", "repo.file.write"]

[[mcp.github.rule]]
tool = "pull_request.comment"
decision = "ask"
```

`nobody mcp proxy <server> -- <command>` enforces these rules for JSON-RPC
stdio messages with `method = "tools/call"`. `deny_tools` wins first. Tool
rules can return `allow`, `deny`, or `ask`; ask fails closed until approval
gates are implemented. Calls that do not match `allow_tools` are denied.

Tool names support simple `*` wildcards. Trace events record server, tool, and
request id, but not tool arguments.

## Trace path

`trace.path` selects the append-only JSONL trace file. If it is omitted,
`nobody` writes to `.nobody/runs/latest.jsonl`.
