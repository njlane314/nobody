# Examples

Run an allowed command.

```sh
cargo run -- run -- echo hello
```

Inspect the latest trace.

```sh
cat .nobody/runs/latest.jsonl
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
started.
