# nobody

Run agents without ambient authority.

nobody is a least-privilege runtime for autonomous software. It runs agents,
tools, MCP servers, and shell commands inside explicit capability boundaries:
filesystem, network, process, secrets, and tool access are granted by policy,
enforced at runtime, and recorded as a replayable trace.

Agents should run as nobody.

## Future CLI

```sh
nobody run --profile coding-agent -- claude-code
nobody trace show latest
nobody diff latest
nobody mcp proxy --policy nobody.toml github
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

This repo is currently a prototype. The company version is a serious systems
product: a Unix-style execution primitive for the agent era.

## Current prototype

`nobody` currently provides the first product surface only: it reads
`nobody.toml`, parses a simple capability policy, gates shell commands by an
allow/deny list, runs the allowed command, and appends JSONL trace events.

It is not a security sandbox yet. There is no Landlock, seccomp, namespace,
network, MCP, or browser-control enforcement in this milestone.

```sh
cargo run -- run -- echo hello
cargo run -- run -- rm -rf /tmp/something
cat .nobody/runs/latest.jsonl
```

Next implementation steps:

1. Add trace schema stability.
2. Add filesystem denial checks before command execution.
3. Add a Linux-only sandbox module.
4. Add Landlock enforcement.
5. Add network namespace/proxy enforcement.
6. Add MCP proxying.
