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

## Next implementation steps

1. Add trace schema stability.
2. Add filesystem denial checks before command execution.
3. Add a Linux-only sandbox module.
4. Add Landlock enforcement.
5. Add network namespace/proxy enforcement.
6. Add MCP proxying.
