# Roadmap

This repo now has the first stable local runtime surface. The company version
is a broader systems product: a Unix-style execution primitive for the agent
era.

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
- 0.7: Linux deny-all network egress enforcement.
- 0.8: Agent profiles.
- 0.9: MCP stdio proxy.
- 1.0: Stable local agent runtime. Current.

## Post-1.0 implementation steps

1. Keep CI focused on explicit runtime guarantees: Linux Landlock, Linux netns deny-all, macOS Seatbelt, escape tests, MCP proxy allow/deny, and generated profiles.
2. Document the Linux Landlock ABI v3 kernel requirement.
3. Add a network proxy/namespace bridge for host allowlists.
4. Add terminal approval gates for policy decisions that should ask instead of deny.
5. Add network and MCP proxy hardening for non-stdio transports and host allowlists.

## Current guarantees

`nobody` currently enforces process allow/deny checks, argument-aware process
rules, and environment filtering before the child process starts. On Linux, it
also installs a Landlock filesystem boundary for policies that can be expressed
as granted read/write paths and can deny all network egress with a fresh network
namespace when `net.deny = ["*"]`.
On macOS, it installs a Seatbelt sandbox profile for filesystem read/write
boundaries and deny-all network egress.

`nobody` currently records structured trace events for run lifecycle, process
decisions, failed setup paths, environment filtering, and sandbox backend
status. `nobody trace explain` summarizes the latest run as a readable
timeline.

`nobody doctor` reports the policy shape, current sandbox backend, filesystem
enforcement status, network enforcement status, warnings, and whether the local
runtime is ready to run under the selected policy. It also repeats key limits:
MCP mediation is proxy-only, host network allowlists are diagnostic, browser
actions are not enforced, and approvals fail closed.

`nobody init` generates profile-based starter policies for Rust, Node, Python,
readonly review, and CI workflows. Profiles write plain TOML and include only
filesystem paths that already exist in the current directory.

`nobody mcp proxy` mediates JSON-RPC stdio `tools/call` messages with
`[mcp.<server>]` allow/deny policy. It records tool-call decisions without tool
arguments. MCP traffic that is not routed through `nobody mcp proxy` is out of
scope.

`nobody` currently simulates filesystem and network policy decisions for
diagnostics. Filesystem simulation may express deny carve-outs that Landlock
cannot enforce under an already-granted path, so the Linux runtime fails closed
for those policies. Network host allowlists explain what policy says; they are
not raw egress allowlist enforcement yet.

`nobody` does not yet enforce browser, sandbox boundaries outside Linux/macOS,
network host allowlists, or MCP traffic that is not routed through
`nobody mcp proxy`.
Proxy-only network controls remain future work because they would be too easy
to overstate as raw socket containment.
