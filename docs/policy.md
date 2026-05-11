# Policy format

`nobody` reads policy from `nobody.toml`.

The current prototype parses agent, task, filesystem, network, process,
environment, approval, and trace sections. Process policy and environment
filtering are enforced today. Other capability sections describe the intended
policy surface and are parsed so the file shape can stabilize before enforcement
lands.

## Example

```toml
[agent]
name = "coding-agent"
kind = "local-cli"

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

[env]
clear = true
allow = ["PATH", "HOME", "USER", "LOGNAME", "LANG", "TERM", "SHELL"]
deny = ["*TOKEN*", "*KEY*", "AWS_*", "DATABASE_URL", "SSH_AUTH_SOCK"]

[approval]
require = ["process.unlisted"]

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
```

## Processes

`process.deny` always wins. If `process.allow` is empty, processes are allowed
unless denied. If `process.allow` is non-empty, a process must appear in that
list and must not appear in `process.deny`.

Commands match either the exact program string or its basename. For example,
`git` matches both `git` and `/usr/bin/git`.

## Filesystem

Filesystem policy is parsed and evaluated by the policy crate. It is not yet
enforced by the runtime.

Filesystem simulation normalizes paths lexically before matching rules. For
example, `./src/../.env` is evaluated as `.env`. It also compares `~/...`
patterns against the current `HOME` path, so `~/.ssh` still matches after a
shell expands it to an absolute path. Explicit `fs.deny` rules win over read
and write grants.

```sh
nobody policy simulate nobody.toml -- fs.read .env
```

```text
DENY fs.read .env
rule: fs.deny
matched: .env
reason: path is explicitly denied
note: filesystem decisions are diagnostics only; OS filesystem enforcement is not active yet
```

## Environment

When `env.clear = true`, the runtime clears inherited environment variables and
re-adds only variables that match `env.allow` and do not match `env.deny`.

When `env.clear = false`, variables are inherited unless they match `env.deny`.

Trace events include variable names and counts, but not values.

## Network

Network policy is parsed and can be evaluated by the policy crate, but network
traffic is not enforced by the runtime yet.

With `mode = "deny-by-default"`, endpoints must match `net.allow` unless they
match an explicit `net.deny` rule. Explicit deny rules win.

## Trace path

`trace.path` selects the append-only JSONL trace file. If it is omitted,
`nobody` writes to `.nobody/runs/latest.jsonl`.
