# Examples

Create a starter policy.

```sh
cargo run -- init --profile rust-coding-agent
cargo run -- init --list-profiles
```

Run an allowed command.

```sh
cargo run -- run -- echo hello
```

Check what this host and policy will actually enforce.

```sh
cargo run -- doctor
cargo run -- doctor --policy nobody.toml
```

`doctor` reports the active policy, process rules, environment filtering, MCP
servers, sandbox backend, filesystem enforcement status, network enforcement
status, and policy warnings.

Inspect the latest trace.

```sh
cargo run -- trace show latest
cargo run -- trace show latest --jsonl
cargo run -- trace explain latest
```

Run with an explicit policy path.

```sh
cargo run -- run --policy nobody.toml -- echo hello
```

Try a denied command.

```sh
cargo run -- run -- curl https://example.com
```

The default `nobody.toml` denies `curl`, so the command is blocked before it is
started and the denial is recorded in the trace as a completed failed run.

Check a policy file.

```sh
cargo run -- policy check nobody.toml
```

`policy check` summarizes process, filesystem, network, environment, and trace
shape and prints warnings for risky legacy process allows,
Landlock-incompatible deny carve-outs, or diagnostic network allowlists.

Simulate policy decisions without running anything.

```sh
cargo run -- policy simulate nobody.toml -- process.exec curl
cargo run -- policy simulate nobody.toml -- process.exec cargo test --workspace
cargo run -- policy simulate nobody.toml -- process.exec python -c 'print(1)'
cargo run -- policy simulate nobody.toml -- env.read GITHUB_TOKEN
cargo run -- policy simulate nobody.toml -- fs.read .env
cargo run -- policy simulate nobody.toml -- net.connect github.com:443
cargo run -- policy simulate nobody.toml -- mcp.tool github issue.read
```

Argument-aware process rules allow conservative forms such as `cargo test` and
deny risky interpreter forms such as `python -c` unless a policy explicitly
allows that argv prefix.

Filesystem simulation is diagnostic only in this prototype. It explains the
policy decision. `nobody run` installs a Landlock filesystem boundary on Linux
when the policy can be represented by allowlisted paths; on non-Linux hosts it
prints a warning and records that filesystem enforcement is inactive.

For Linux deny-all network egress, set:

```toml
[net]
mode = "deny-by-default"
allow = []
deny = ["*"]
```

Host allowlists are currently diagnostic; deny-all is the enforced network
primitive in 0.7.

Proxy an MCP server over stdio.

```sh
cargo run -- mcp proxy github --policy nobody.toml -- <mcp-server-command>
```

The proxy checks `tools/call` messages against `[mcp.github]` before forwarding
them. Denied calls receive JSON-RPC error responses and are recorded in the
trace without tool arguments.
