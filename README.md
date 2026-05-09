# nobody

Run programs with explicit capabilities.

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
