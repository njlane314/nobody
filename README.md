# nobody

Run agents without ambient authority.

[![build](https://img.shields.io/github/actions/workflow/status/njlane314/nobody/ci.yml?branch=main&label=build)](https://github.com/njlane314/nobody/actions/workflows/ci.yml)
[![status](https://img.shields.io/badge/status-local_runtime-blue)](docs/roadmap.md)

nobody is a least-privilege execution runtime for AI agents.

nobody is designed to run autonomous software as a process with declared
capabilities instead of inherited authority. The current runtime enforces
process and environment policy, applies Linux Landlock filesystem boundaries
when available, can deny all Linux network egress with a network namespace,
mediates MCP tool calls routed through its stdio proxy, records structured
trace evidence, and exposes host-level network allowlists as policy diagnostics
until proxy-backed allowlist enforcement lands.

Agents should run as nobody.

## Build

```sh
make
make check
```

## Run

```sh
cargo run -- init --list-profiles
cargo run -- doctor
cargo run -- run -- echo hello
cargo run -- policy simulate nobody.toml -- fs.read .env
cargo run -- trace show latest
```

```text
agent / coding tool / MCP client
        |
        v
     nobody
        |
        +--> filesystem capabilities
        +--> network capabilities
        +--> process capabilities
        +--> MCP/tool capabilities
        +--> secrets capabilities
        +--> approval gates
        +--> append-only trace
        |
        v
   actual OS / APIs / repos / SaaS tools
```

## Current local runtime

This repo currently provides the first product surface only: it reads
`nobody.toml`, parses a typed capability policy, evaluates process and
environment decisions, runs the allowed command, filters inherited environment
variables, and appends structured JSONL trace events.

`nobody doctor` reports the active policy shape and sandbox backend before a
run, including whether filesystem and network enforcement are active or only
diagnostic on the current host.

Currently enforced:

- process allow/deny and argument-aware process rules before a command is spawned
- environment filtering by allow/deny patterns
- Linux filesystem read/write boundaries through Landlock when the policy can
  be represented without deny carve-outs under granted paths
- Linux deny-all network egress through a fresh network namespace when policy
  uses `net.deny = ["*"]`
- MCP `tools/call` allow/deny policy for JSON-RPC stdio traffic routed through
  `nobody mcp proxy`

Currently recorded:

- run creation and completion
- policy load
- process decision, start, and exit
- environment filtering summary without variable values
- sandbox backend and enforcement status
- failed setup decisions as completed failed runs
- filesystem and network policy simulation
- MCP proxy and tool-call decisions without tool arguments
- readable run summaries through `nobody trace explain`

Currently generated:

- profile-based `nobody init` templates for common coding and review agents

Filesystem escape tests live under `tests/escape/` and cover denied reads
through shells, interpreters, symlinks, traversal, package scripts, and build
scripts.

Not enforced yet:

- filesystem read/write boundaries on non-Linux hosts
- host allowlist network egress
- MCP transports not routed through `nobody mcp proxy`
- browser sessions
- seccomp, namespace isolation beyond deny-all networking, or macOS sandboxing

## Documentation

- [Design note](docs/design.html)
- [Design PDF](docs/design.pdf)
- [Policy format](docs/policy.md)
- [Agent profiles](docs/profiles.md)
- [MCP proxy](docs/mcp.md)
- [Trace format](docs/trace.md)
- [Examples](docs/examples.md)
- [Roadmap](docs/roadmap.md)
