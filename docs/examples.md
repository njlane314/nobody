# Examples

Run an allowed command.

```sh
cargo run -- run -- echo hello
```

Inspect the latest trace.

```sh
cargo run -- trace show latest
cargo run -- trace show latest --jsonl
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
started and the denial is recorded in the trace.

Check a policy file.

```sh
cargo run -- policy check nobody.toml
```

Simulate policy decisions without running anything.

```sh
cargo run -- policy simulate nobody.toml -- process.exec curl
cargo run -- policy simulate nobody.toml -- env.read GITHUB_TOKEN
cargo run -- policy simulate nobody.toml -- fs.read .env
```

Filesystem simulation is diagnostic only in this prototype. It explains the
policy decision. `nobody run` installs a Landlock filesystem boundary on Linux
when the policy can be represented by allowlisted paths; on non-Linux hosts it
prints a warning and records that filesystem enforcement is inactive.
