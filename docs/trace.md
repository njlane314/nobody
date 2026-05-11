# Trace format

`nobody` writes newline-delimited JSON events to the configured trace path.

Each event has:

- `schema_version`: trace schema identifier.
- `run_id`: runtime-generated run identifier.
- `event_id`: event identifier within the run.
- `parent_event_id`: optional parent event.
- `ts_ms`: Unix timestamp in milliseconds.
- `actor`: event writer identity.
- `kind`: event name.
- `decision`: optional policy decision summary.
- `data`: event payload.

## Events

`run.created` records the requested command.

```json
{"schema_version":"nobody.trace.v1","run_id":"run-1760000000000-1","event_id":"evt-1","parent_event_id":null,"ts_ms":1760000000000,"actor":{"kind":"runtime","id":"local"},"kind":"run.created","decision":null,"data":{"command":["echo","hello"]}}
```

`process.exec.allow` or `process.exec.deny` records the authorization decision
before the runtime spawns a process.

```json
{"schema_version":"nobody.trace.v1","run_id":"run-1760000000000-1","event_id":"evt-3","parent_event_id":null,"ts_ms":1760000000002,"actor":{"kind":"runtime","id":"local"},"kind":"process.exec.allow","decision":{"decision":"allow","rule_id":"process.allow","resource":{"kind":"process","program":"echo","argv":["hello"]},"action":"process_exec","matched_pattern":"echo","message":"process matched allow list"},"data":{"program":"echo","argv":["hello"]}}
```

`env.filtered` records the number and names of allowed and denied inherited
environment variables. It does not record values.

`sandbox.prepared` records the selected sandbox backend and whether filesystem
and network enforcement are active for the run.

`process.started` and `process.exited` record process lifecycle details.

`run.completed` records the final exit status. If a run is denied before spawn
or fails while preparing the sandbox, `run.completed` records `success=false`,
a machine-readable `reason`, and an error message.

## Viewer

Show the latest trace in a compact terminal view:

```sh
nobody trace show latest
nobody trace show latest --jsonl
nobody trace explain latest
```

The default view is a compact human-readable summary. `--jsonl` prints the
selected events as newline-delimited JSON.

`trace explain` turns the selected run into an incident-style summary with the
command, policy path, sandbox backend, duration, exit status, and a readable
timeline of decisions and runtime events.

```text
Run run-...
Command: cargo test
Policy: nobody.toml
Sandbox: backend=landlock+netns enforced=true fs=true net=true network_mode=deny-all
Duration: 8.320s
Exit: code=0 success=true

Timeline:
   0.000s run.created cargo test
   0.004s policy.loaded path=nobody.toml trace=.nobody/runs/latest.jsonl
   0.007s process.exec ALLOW cargo test rule=process.rule.allow_args
   0.009s env.filtered allowed=7 denied=42
   0.015s sandbox.prepared backend=landlock+netns enforced=true fs=true net=true network_mode=deny-all
   8.320s run.completed code=0 success=true
```

A denied setup path still has a trace footer:

```text
Timeline:
   0.000s run.created curl https://example.com
   0.004s policy.loaded path=nobody.toml trace=.nobody/runs/latest.jsonl
   0.007s process.exec DENY curl rule=process.deny matched=curl
   0.008s run.completed code=signal success=false
```

MCP proxy runs additionally record `mcp.proxy.created`, `mcp.proxy.started`,
`mcp.tool.allow` or `mcp.tool.deny`, and `mcp.proxy.exited`. Tool-call events
record server, tool, and request id, but not tool arguments.

## Current limitations

The trace is append-only by convention in the current prototype. It is not yet
sealed, signed, replayable, or protected against local modification.

The trace schema is designed for more detailed filesystem, network, approval,
and MCP events. The current runtime records sandbox preparation, deny-all
network backend status, and MCP proxy decisions, but it does not yet record
every file access attempted inside the child process or every socket attempt
inside the network namespace.
