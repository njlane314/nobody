# nobody

Run agents without ambient authority.

[![build](https://img.shields.io/github/actions/workflow/status/njlane314/nobody/ci.yml?branch=main&label=build)](https://github.com/njlane314/nobody/actions/workflows/ci.yml)
[![status](https://img.shields.io/badge/status-prototype-orange)](docs/roadmap.md)

nobody is a least-privilege execution runtime for AI agents.

nobody runs autonomous software as a process with declared capabilities instead
of inherited authority. Agents, tools, MCP servers, and shell commands run
inside explicit capability boundaries: filesystem, network, process, secrets,
and tool access are granted by policy, enforced at runtime, and recorded as a
replayable trace.

Agents should run as nobody.

## Build

```sh
make
make check
```

## Run

```sh
cargo run -- run -- echo hello
cat .nobody/runs/latest.jsonl
```

```text
agent / coding tool / MCP client
        |
        v
     nobody
        |
        +--> filesystem capabilities
        +--> network capabilities
        +--> shell/process capabilities
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
`nobody.toml`, parses a simple capability policy, gates shell commands by an
allow/deny list, runs the allowed command, and appends JSONL trace events.

It is not a security sandbox yet. There is no Landlock, seccomp, namespace,
network, MCP, or browser-control enforcement in this milestone.

## Documentation

- [Policy format](docs/policy.md)
- [Trace format](docs/trace.md)
- [Examples](docs/examples.md)
- [Roadmap](docs/roadmap.md)
