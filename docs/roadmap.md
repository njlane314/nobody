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

## Release sequence

- 0.3: Linux filesystem enforcement.
- 0.4: Escape-test suite.
- 0.5: Process and environment hardening.
- 0.6: Trace viewer and policy diagnostics polish.
- 0.7: Network egress enforcement.
- 0.8: Agent profiles.
- 0.9: MCP proxy.
- 1.0: Stable local agent runtime.

## Next implementation steps

1. Validate the Linux Landlock backend in CI and document the ABI v3 kernel requirement.
2. Make `tests/escape/` the first-class guarantee suite for interpreter and build-system escapes.
3. Polish trace explanation and policy diagnostics.
4. Add network namespace/proxy enforcement only after filesystem escape tests are stable.
5. Add profile-based `nobody init` defaults for Rust, Node, Python, readonly review, and CI agents.

## Current guarantees

`nobody` currently enforces process allow/deny checks, argument-aware process
rules, and environment filtering before the child process starts. On Linux, it
also installs a Landlock filesystem boundary for policies that can be expressed
as granted read/write paths.

`nobody` currently records structured trace events for run lifecycle, process
decisions, environment filtering, and sandbox backend status.

`nobody` currently simulates filesystem and network policy decisions for
diagnostics. Filesystem simulation may express deny carve-outs that Landlock
cannot enforce under an already-granted path, so the Linux runtime fails closed
for those policies. Network decisions explain what policy says; they are not
operating system enforcement yet.

`nobody` does not yet enforce network, MCP, browser, or cross-OS sandbox
boundaries. Network is intentionally after filesystem enforcement and escape
tests because proxy-only controls would be too easy to overstate.
