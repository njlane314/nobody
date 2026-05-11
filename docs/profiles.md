# Agent profiles

`nobody init` writes a starter `nobody.toml` for a common agent workflow.

```sh
nobody init
nobody init --profile rust-coding-agent
nobody init --profile readonly-review-agent --output review.toml
nobody init --list-profiles
```

If `--profile` is omitted, `nobody` detects the profile from the current
directory:

- `Cargo.toml`: `rust-coding-agent`
- `package.json`: `node-coding-agent`
- `pyproject.toml`, `setup.py`, or `requirements.txt`: `python-coding-agent`
- otherwise: `readonly-review-agent`

Profiles are policy templates, not hidden runtime behavior. They generate a
plain TOML file that should be reviewed and committed like any other project
configuration.

## Built-in profiles

- `rust-coding-agent`: Cargo-oriented Rust development.
- `node-coding-agent`: Node development with npm, pnpm, yarn, or bun.
- `python-coding-agent`: Python development with pytest, pip, uv, and ruff.
- `readonly-review-agent`: read-only review with deny-all network egress.
- `ci-agent`: local test and build commands across common stacks.

## Filesystem grants

Generated profiles include only paths that already exist in the current
directory. This keeps Linux Landlock honest: `nobody init` does not generate
`read = ["."]` with `.env` carve-outs that the sandbox cannot enforce.

For example, a Rust repo with `Cargo.toml`, `src/`, and `tests/` receives grants
for those paths. Missing directories such as `examples/` are omitted until they
exist and the policy is regenerated or edited.

## Network defaults

Coding profiles include package-registry host allowlists for policy simulation.
Those host allowlists are diagnostic in the current runtime. The enforced
network primitive on Linux and macOS is deny-all egress with:

```toml
[net]
mode = "deny-by-default"
allow = []
deny = ["*"]
```

The `readonly-review-agent` profile uses that deny-all network shape by
default.
