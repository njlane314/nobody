# Trace format

`nobody` writes newline-delimited JSON events to the configured trace path.

Each event has:

- `ts_ms`: Unix timestamp in milliseconds.
- `kind`: event name.
- `data`: event payload.

## Events

`run.start` records the command, arguments, and policy file.

```json
{"ts_ms":1760000000000,"kind":"run.start","data":{"program":"echo","argv":["hello"],"policy":"nobody.toml"}}
```

`run.exit` records the process exit status.

```json
{"ts_ms":1760000000100,"kind":"run.exit","data":{"code":0,"success":true}}
```

## Current limitations

The trace is append-only by convention in the current prototype. It is not yet
sealed, signed, replayable, or protected against local modification.
