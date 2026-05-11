# MCP proxy

`nobody mcp proxy` mediates MCP tool calls over stdio.

```sh
nobody mcp proxy github --policy nobody.toml -- <mcp-server-command>
```

The proxy reads JSON-RPC messages from stdin, forwards allowed messages to the
server process, and writes server responses to stdout. Calls with
`method = "tools/call"` are checked against `[mcp.<server>]` policy before they
reach the server.

Denied tool calls are not forwarded. If the request has a JSON-RPC `id`, the
proxy returns an error response to the client.

## Policy

```toml
[mcp.github]
allow_tools = [
  "issue.read",
  "pull_request.read",
  "repo.file.read",
]
deny_tools = [
  "pull_request.merge",
  "repo.file.write",
]

[[mcp.github.rule]]
tool = "pull_request.comment"
decision = "ask"
```

`deny_tools` wins over rules and allow lists. `allow_tools` is deny-by-default:
a tool that does not match the allow list is denied. `decision = "ask"` fails
closed until approval gates exist.

Tool patterns support the same simple `*` wildcard matching used elsewhere in
policy evaluation.

## Trace

The proxy records:

- `mcp.proxy.created`
- `process.exec.allow` or `process.exec.deny` for the server command
- `env.filtered`
- `mcp.proxy.started`
- `mcp.tool.allow`, `mcp.tool.deny`, or `mcp.tool.ask`
- `mcp.proxy.exited`

Tool-call trace events include the server, tool name, and request id. They do
not record tool arguments.

## Limits

This is a stdio proxy skeleton. It only mediates MCP traffic that is routed
through `nobody mcp proxy`. It does not yet discover MCP server schemas,
redact tool arguments by schema, support approvals, or proxy non-stdio
transports.
