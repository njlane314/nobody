# nobody

Run agents without ambient authority.

nobody is a least-privilege execution runtime for AI agents.

nobody runs autonomous software as a process with declared capabilities instead
of inherited authority. Agents, tools, MCP servers, and shell commands run
inside explicit capability boundaries: filesystem, network, process, secrets,
and tool access are granted by policy, enforced at runtime, and recorded as a
replayable trace.

Agents should run as nobody.

## Future CLI

```sh
# setup
nobody init
nobody doctor

# execution
nobody run --policy nobody.toml -- <command>
nobody run --profile coding-agent -- <command>

# policy
nobody explain nobody.toml
nobody policy check nobody.toml
nobody policy simulate nobody.toml
nobody policy compile nobody.toml

# traces
nobody trace list
nobody trace show latest
nobody trace diff latest
nobody trace replay latest
nobody trace export latest --format jsonl

# approvals
nobody approve list
nobody approve show <id>
nobody approve grant <id>
nobody approve deny <id>

# MCP
nobody mcp proxy github --policy nobody.toml
nobody mcp tools github
nobody mcp explain github.pull_request.merge

# enterprise
nobody login
nobody org policies
nobody org runs
nobody runner register
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
