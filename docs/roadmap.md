# Roadmap

This repo is currently a prototype. The company version is a serious systems
product: a Unix-style execution primitive for the agent era.

## Future command surface

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
nobody policy simulate nobody.toml -- fs.read .env
nobody policy simulate nobody.toml -- process.exec curl
nobody policy compile nobody.toml

# traces
nobody trace list
nobody trace show latest
nobody trace show latest --jsonl
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

## Next implementation steps

1. Add a Linux-only sandbox crate interface.
2. Add Landlock filesystem enforcement.
3. Add escape tests for denied `.env`, SSH keys, symlink traversal, and child-process file access.
4. Add network namespace/proxy enforcement.
5. Add MCP proxying.

## Current guarantees

`nobody` currently enforces process allow/deny checks before spawning a command
and filters environment variables before the child process starts.

`nobody` currently records structured trace events for run lifecycle, process
decisions, and environment filtering.

`nobody` currently simulates filesystem and network policy decisions for
diagnostics. These decisions explain what policy says; they are not operating
system enforcement yet.

`nobody` does not yet enforce filesystem, network, MCP, browser, or cross-OS
sandbox boundaries.
