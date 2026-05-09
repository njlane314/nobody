# Policy format

`nobody` reads policy from `nobody.toml`.

The current prototype parses filesystem, network, shell, and trace sections.
Only shell command allow and deny lists are enforced today. Other capability
sections describe the intended policy surface and are parsed so the file shape
can stabilize before enforcement lands.

## Example

```toml
[fs]
read = ["./"]
write = ["./src", "./tests"]
deny = [".env", "~/.ssh", "~/.aws"]

[net]
allow = ["github.com", "api.anthropic.com"]
deny = ["*"]

[shell]
allow = ["echo", "git", "cargo", "rustc"]
deny = ["rm", "curl", "scp", "ssh"]

[trace]
path = ".nobody/runs/latest.jsonl"
```

## Shell commands

`shell.deny` always wins. If `shell.allow` is empty, commands are allowed
unless denied. If `shell.allow` is non-empty, a command must appear in that list
and must not appear in `shell.deny`.

Commands match either the exact program string or its basename. For example,
`git` matches both `git` and `/usr/bin/git`.

## Trace path

`trace.path` selects the append-only JSONL trace file. If it is omitted,
`nobody` writes to `.nobody/runs/latest.jsonl`.
