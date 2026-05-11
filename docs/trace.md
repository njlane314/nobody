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

`process.started` and `process.exited` record process lifecycle details.

`run.completed` records the final exit status.

## Viewer

Show the latest trace in a compact terminal view:

```sh
nobody trace show latest
nobody trace show latest --jsonl
```

The default view is a compact human-readable summary. `--jsonl` prints the
selected events as newline-delimited JSON.

## Current limitations

The trace is append-only by convention in the current prototype. It is not yet
sealed, signed, replayable, or protected against local modification.

The trace schema is designed for filesystem, network, approval, and MCP events,
but those enforcement points have not landed yet.
