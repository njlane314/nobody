# nobody

Run agents without ambient authority.

[![build](https://img.shields.io/github/actions/workflow/status/njlane314/nobody/ci.yml?branch=main&label=build)](https://github.com/njlane314/nobody/actions/workflows/ci.yml)
[![status](https://img.shields.io/badge/status-prototype-orange)](docs/roadmap.md)

nobody is a least-privilege execution runtime for AI agents.

nobody is designed to run autonomous software as a process with declared
capabilities instead of inherited authority. The current runtime enforces
process and environment policy, applies Linux Landlock filesystem boundaries
when available, records structured trace evidence, and exposes network
decisions as policy diagnostics before that enforcement backend lands.

Agents should run as nobody.

## Build

```sh
make
make check
```

## Run

```sh
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

## Current prototype

This repo currently provides the first product surface only: it reads
`nobody.toml`, parses a typed capability policy, evaluates process and
environment decisions, runs the allowed command, filters inherited environment
variables, and appends structured JSONL trace events.

Currently enforced:

- process allow/deny and argument-aware process rules before a command is spawned
- environment filtering by allow/deny patterns
- Linux filesystem read/write boundaries through Landlock when the policy can
  be represented without deny carve-outs under granted paths

Currently recorded:

- run creation and completion
- policy load
- process decision, start, and exit
- environment filtering summary without variable values
- sandbox backend and enforcement status
- filesystem and network policy simulation

Filesystem escape tests live under `tests/escape/` and cover denied reads
through shells, interpreters, symlinks, traversal, package scripts, and build
scripts.

Not enforced yet:

- filesystem read/write boundaries on non-Linux hosts
- network egress
- MCP tool calls
- browser sessions
- seccomp, namespaces, or macOS sandboxing

## Documentation

- [Design note](docs/design.html)
- [Design PDF](docs/design.pdf)
- [Policy format](docs/policy.md)
- [Trace format](docs/trace.md)
- [Examples](docs/examples.md)
- [Roadmap](docs/roadmap.md)
