use anyhow::Result;
use nobody_policy::Decision;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt::Write as FmtWrite;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static RUN_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub schema_version: String,
    pub run_id: String,
    pub event_id: String,
    pub parent_event_id: Option<String>,
    pub ts_ms: u128,
    pub actor: Actor,
    pub kind: String,
    pub decision: Option<DecisionSummary>,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionSummary {
    pub decision: String,
    pub rule_id: Option<String>,
    pub resource: Value,
    pub action: String,
    pub matched_pattern: Option<String>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
struct LegacyTraceEvent {
    ts_ms: u128,
    kind: String,
    data: Value,
}

pub struct TraceWriter {
    file: File,
    run_id: String,
    next_event: u64,
}

impl TraceWriter {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            file,
            run_id: new_run_id(),
            next_event: 1,
        })
    }

    pub fn event(
        &mut self,
        kind: &str,
        decision: Option<DecisionSummary>,
        data: Value,
    ) -> Result<()> {
        let event = TraceEvent {
            schema_version: "nobody.trace.v1".into(),
            run_id: self.run_id.clone(),
            event_id: format!("evt-{}", self.next_event),
            parent_event_id: None,
            ts_ms: now_ms()?,
            actor: Actor {
                kind: "runtime".into(),
                id: "local".into(),
            },
            kind: kind.into(),
            decision,
            data,
        };

        self.next_event += 1;

        serde_json::to_writer(&mut self.file, &event)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;

        Ok(())
    }
}

impl DecisionSummary {
    pub fn from_policy_decision(decision: &Decision) -> Self {
        let reason = decision.reason();

        Self {
            decision: decision.kind().to_string(),
            rule_id: reason.rule_id.clone(),
            resource: serde_json::to_value(&reason.resource)
                .unwrap_or_else(|_| json!({ "error": "resource_not_serializable" })),
            action: serde_json::to_value(&reason.action)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| format!("{:?}", reason.action)),
            matched_pattern: reason.matched_pattern.clone(),
            message: reason.message.clone(),
        }
    }

    pub fn event_kind(&self, base: &str) -> String {
        format!("{base}.{}", self.decision)
    }
}

pub fn read_events(path: &Path) -> Result<Vec<TraceEvent>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(&line) {
            Ok(event) => events.push(event),
            Err(_) => {
                let legacy: LegacyTraceEvent = serde_json::from_str(&line)?;
                events.push(TraceEvent {
                    schema_version: "nobody.trace.legacy".into(),
                    run_id: "legacy".into(),
                    event_id: format!("legacy-{}", index + 1),
                    parent_event_id: None,
                    ts_ms: legacy.ts_ms,
                    actor: Actor {
                        kind: "runtime".into(),
                        id: "local".into(),
                    },
                    kind: legacy.kind,
                    decision: None,
                    data: legacy.data,
                });
            }
        }
    }

    Ok(events)
}

pub fn format_events(events: &[TraceEvent]) -> String {
    let mut out = String::new();

    if let Some(first) = events.first() {
        let _ = writeln!(&mut out, "Run {}", first.run_id);
    }

    let start = events.first().map(|event| event.ts_ms).unwrap_or(0);

    for event in events {
        let elapsed_ms = event.ts_ms.saturating_sub(start);
        let decision = event
            .decision
            .as_ref()
            .map(|summary| format!(" {}", summary.decision.to_uppercase()))
            .unwrap_or_default();
        let detail = event_detail(event);

        if detail.is_empty() {
            let _ = writeln!(
                &mut out,
                "{:>8.3}s {}{}",
                elapsed_ms as f64 / 1000.0,
                event.kind,
                decision
            );
        } else {
            let _ = writeln!(
                &mut out,
                "{:>8.3}s {}{} {}",
                elapsed_ms as f64 / 1000.0,
                event.kind,
                decision,
                detail
            );
        }
    }

    out
}

pub fn format_events_explain(events: &[TraceEvent]) -> String {
    let mut out = String::new();
    let Some(first) = events.first() else {
        return out;
    };

    let last = events.last().unwrap_or(first);
    let duration_ms = last.ts_ms.saturating_sub(first.ts_ms);

    let _ = writeln!(&mut out, "Run {}", first.run_id);
    if let Some(command) = events.iter().find_map(command_from_event) {
        let _ = writeln!(&mut out, "Command: {command}");
    }
    if let Some(policy) = events.iter().find_map(policy_from_event) {
        let _ = writeln!(&mut out, "Policy: {policy}");
    }
    if let Some(sandbox) = events.iter().find_map(sandbox_from_event) {
        let _ = writeln!(&mut out, "Sandbox: {sandbox}");
    }
    let _ = writeln!(&mut out, "Duration: {:.3}s", duration_ms as f64 / 1000.0);
    if let Some(exit) = events.iter().rev().find_map(exit_from_event) {
        let _ = writeln!(&mut out, "Exit: {exit}");
    }

    out.push('\n');
    out.push_str("Timeline:\n");

    for event in events {
        let elapsed_ms = event.ts_ms.saturating_sub(first.ts_ms);
        let _ = writeln!(
            &mut out,
            "{:>8.3}s {}",
            elapsed_ms as f64 / 1000.0,
            explain_event(event)
        );
    }

    out
}

pub fn format_events_jsonl(events: &[TraceEvent]) -> Result<String> {
    let mut out = String::new();

    for event in events {
        out.push_str(&serde_json::to_string(event)?);
        out.push('\n');
    }

    Ok(out)
}

fn explain_event(event: &TraceEvent) -> String {
    if let Some(summary) = &event.decision {
        let mut parts = vec![
            decision_base_kind(&event.kind, &summary.decision),
            summary.decision.to_uppercase(),
        ];

        if let Some(resource) = compact_resource(&summary.resource) {
            parts.push(resource);
        }

        if let Some(rule_id) = &summary.rule_id {
            parts.push(format!("rule={rule_id}"));
        }

        if let Some(pattern) = &summary.matched_pattern {
            parts.push(format!("matched={pattern}"));
        }

        return parts.join(" ");
    }

    match event.kind.as_str() {
        "run.created" => command_from_event(event)
            .map(|command| format!("run.created {command}"))
            .unwrap_or_else(|| event.kind.clone()),
        "policy.loaded" => {
            let path = event
                .data
                .get("path")
                .map(value_to_text)
                .unwrap_or_else(|| "(unknown)".into());
            let trace = event
                .data
                .get("trace_path")
                .map(value_to_text)
                .unwrap_or_else(|| "(unknown)".into());
            format!("policy.loaded path={path} trace={trace}")
        }
        "env.filtered" => {
            let allowed = event
                .data
                .get("allowed_count")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let denied = event
                .data
                .get("denied_count")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            format!("env.filtered allowed={allowed} denied={denied}")
        }
        "sandbox.prepared" => sandbox_from_event(event)
            .map(|sandbox| format!("sandbox.prepared {sandbox}"))
            .unwrap_or_else(|| event.kind.clone()),
        "sandbox.prepare.failed" | "process.start.failed" | "process.wait.failed" => {
            let detail = event_detail(event);
            if detail.is_empty() {
                event.kind.clone()
            } else {
                format!("{} {detail}", event.kind)
            }
        }
        "mcp.proxy.created" => {
            let server = event
                .data
                .get("server")
                .and_then(|value| value.as_str())
                .unwrap_or("(unknown)");
            format!("mcp.proxy.created server={server}")
        }
        "mcp.proxy.started" => {
            let server = event
                .data
                .get("server")
                .and_then(|value| value.as_str())
                .unwrap_or("(unknown)");
            let pid = event
                .data
                .get("pid")
                .and_then(|value| value.as_u64())
                .map(|pid| format!(" pid={pid}"))
                .unwrap_or_default();
            format!("mcp.proxy.started server={server}{pid}")
        }
        "mcp.proxy.exited" => exit_from_event(event)
            .map(|exit| format!("mcp.proxy.exited {exit}"))
            .unwrap_or_else(|| event.kind.clone()),
        "process.started" => {
            let program = event
                .data
                .get("program")
                .and_then(|value| value.as_str())
                .unwrap_or("(unknown)");
            let pid = event
                .data
                .get("pid")
                .and_then(|value| value.as_u64())
                .map(|pid| format!(" pid={pid}"))
                .unwrap_or_default();
            format!("process.started {program}{pid}")
        }
        "process.exited" | "run.completed" => exit_from_event(event)
            .map(|exit| format!("{} {exit}", event.kind))
            .unwrap_or_else(|| event.kind.clone()),
        _ => {
            let detail = event_detail(event);
            if detail.is_empty() {
                event.kind.clone()
            } else {
                format!("{} {detail}", event.kind)
            }
        }
    }
}

fn decision_base_kind(kind: &str, decision: &str) -> String {
    kind.strip_suffix(&format!(".{decision}"))
        .unwrap_or(kind)
        .to_owned()
}

fn compact_resource(resource: &Value) -> Option<String> {
    match resource.get("kind").and_then(|value| value.as_str())? {
        "process" => {
            let program = resource.get("program")?.as_str()?;
            let argv = resource
                .get("argv")
                .and_then(|value| value.as_array())
                .map(|argv| {
                    argv.iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if argv.is_empty() {
                Some(program.to_owned())
            } else {
                Some(format!("{} {}", program, argv.join(" ")))
            }
        }
        "file" => resource
            .get("path")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        "network" => {
            let host = resource.get("host")?.as_str()?;
            let port = resource.get("port")?.as_u64()?;
            Some(format!("{host}:{port}"))
        }
        "env" => resource
            .get("name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        "mcp_tool" => {
            let server = resource.get("server")?.as_str()?;
            let tool = resource.get("tool")?.as_str()?;
            Some(format!("{server}/{tool}"))
        }
        _ => None,
    }
}

fn command_from_event(event: &TraceEvent) -> Option<String> {
    if !matches!(event.kind.as_str(), "run.created" | "mcp.proxy.created") {
        return None;
    }

    event
        .data
        .get("command")
        .and_then(|value| value.as_array())
        .map(|command| {
            command
                .iter()
                .filter_map(|value| value.as_str())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
                .join(" ")
        })
}

fn policy_from_event(event: &TraceEvent) -> Option<String> {
    match event.kind.as_str() {
        "policy.loaded" => event.data.get("path").map(value_to_text),
        "mcp.proxy.created" => event.data.get("policy_path").map(value_to_text),
        _ => None,
    }
}

fn sandbox_from_event(event: &TraceEvent) -> Option<String> {
    if event.kind != "sandbox.prepared" {
        return None;
    }

    let backend = event.data.get("backend")?.as_str()?;
    let enforced = event
        .data
        .get("enforced")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let mut sandbox = format!("backend={backend} enforced={enforced}");
    if let Some(filesystem_enforced) = event
        .data
        .get("filesystem_enforced")
        .and_then(|value| value.as_bool())
    {
        sandbox.push_str(&format!(" fs={filesystem_enforced}"));
    }
    if let Some(network_enforced) = event
        .data
        .get("network_enforced")
        .and_then(|value| value.as_bool())
    {
        sandbox.push_str(&format!(" net={network_enforced}"));
    }
    if let Some(network_mode) = event
        .data
        .get("network_mode")
        .and_then(|value| value.as_str())
    {
        sandbox.push_str(&format!(" network_mode={network_mode}"));
    }
    if let Some(warning) = event.data.get("warning").and_then(|value| value.as_str()) {
        sandbox.push_str(&format!(" warning={warning}"));
    }
    Some(sandbox)
}

fn exit_from_event(event: &TraceEvent) -> Option<String> {
    if !matches!(
        event.kind.as_str(),
        "process.exited" | "run.completed" | "mcp.proxy.exited"
    ) {
        return None;
    }

    let code = event
        .data
        .get("code")
        .and_then(|value| value.as_i64())
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".into());
    let success = event
        .data
        .get("success")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    Some(format!("code={code} success={success}"))
}

fn value_to_text(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}

pub fn latest_run_events(events: &[TraceEvent]) -> Vec<TraceEvent> {
    let Some(run_id) = events.last().map(|event| event.run_id.as_str()) else {
        return Vec::new();
    };

    events
        .iter()
        .filter(|event| event.run_id == run_id)
        .cloned()
        .collect()
}

fn event_detail(event: &TraceEvent) -> String {
    if let Some(summary) = &event.decision {
        return decision_detail(summary);
    }

    if event.kind == "env.filtered" {
        let allowed = event
            .data
            .get("allowed_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let denied = event
            .data
            .get("denied_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);

        return format!("allowed={allowed} denied={denied}");
    }

    if let Some(program) = event.data.get("program").and_then(|value| value.as_str()) {
        return program.to_owned();
    }

    if let Some(command) = event.data.get("command").and_then(|value| value.as_array()) {
        let parts: Vec<_> = command
            .iter()
            .filter_map(|value| value.as_str())
            .map(ToOwned::to_owned)
            .collect();
        return parts.join(" ");
    }

    if let Some(path) = event.data.get("path").and_then(|value| value.as_str()) {
        return path.to_owned();
    }

    if let Some(error) = event.data.get("error").and_then(|value| value.as_str()) {
        return format!("error={error}");
    }

    if let Some(reason) = event.data.get("reason").and_then(|value| value.as_str()) {
        return format!("reason={reason}");
    }

    String::new()
}

fn decision_detail(summary: &DecisionSummary) -> String {
    let mut detail = summary.message.clone();
    let mut fields = Vec::new();

    if let Some(resource) = resource_detail(&summary.resource) {
        fields.push(resource);
    }

    if let Some(rule_id) = &summary.rule_id {
        fields.push(format!("rule={rule_id}"));
    }

    if let Some(pattern) = &summary.matched_pattern {
        fields.push(format!("matched={pattern}"));
    }

    if !fields.is_empty() {
        detail.push_str(" (");
        detail.push_str(&fields.join(" "));
        detail.push(')');
    }

    detail
}

fn resource_detail(resource: &Value) -> Option<String> {
    match resource.get("kind").and_then(|value| value.as_str())? {
        "process" => {
            let program = resource.get("program")?.as_str()?;
            let argv = resource
                .get("argv")
                .and_then(|value| value.as_array())
                .map(|argv| {
                    argv.iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if argv.is_empty() {
                Some(format!("process={program}"))
            } else {
                Some(format!("process=\"{} {}\"", program, argv.join(" ")))
            }
        }
        "file" => resource
            .get("path")
            .and_then(|value| value.as_str())
            .map(|path| format!("path={path}")),
        "network" => {
            let host = resource.get("host")?.as_str()?;
            let port = resource.get("port")?.as_u64()?;
            Some(format!("endpoint={host}:{port}"))
        }
        "env" => resource
            .get("name")
            .and_then(|value| value.as_str())
            .map(|name| format!("env={name}")),
        "mcp_tool" => {
            let server = resource.get("server")?.as_str()?;
            let tool = resource.get("tool")?.as_str()?;
            Some(format!("tool={server}/{tool}"))
        }
        _ => None,
    }
}

fn new_run_id() -> String {
    let count = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let time = now_ms().unwrap_or(0);
    format!("run-{time}-{count}")
}

fn now_ms() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_events_for_terminal() {
        let events = vec![TraceEvent {
            schema_version: "nobody.trace.v1".into(),
            run_id: "run-1".into(),
            event_id: "evt-1".into(),
            parent_event_id: None,
            ts_ms: 1000,
            actor: Actor {
                kind: "runtime".into(),
                id: "local".into(),
            },
            kind: "run.created".into(),
            decision: None,
            data: json!({ "command": ["echo", "hello"] }),
        }];

        let out = format_events(&events);

        assert!(out.contains("Run run-1"));
        assert!(out.contains("run.created echo hello"));
    }

    #[test]
    fn explains_events_for_terminal() {
        let events = vec![
            TraceEvent {
                schema_version: "nobody.trace.v1".into(),
                run_id: "run-1".into(),
                event_id: "evt-1".into(),
                parent_event_id: None,
                ts_ms: 1000,
                actor: Actor {
                    kind: "runtime".into(),
                    id: "local".into(),
                },
                kind: "run.created".into(),
                decision: None,
                data: json!({ "command": ["cargo", "test"] }),
            },
            TraceEvent {
                schema_version: "nobody.trace.v1".into(),
                run_id: "run-1".into(),
                event_id: "evt-2".into(),
                parent_event_id: None,
                ts_ms: 1001,
                actor: Actor {
                    kind: "runtime".into(),
                    id: "local".into(),
                },
                kind: "policy.loaded".into(),
                decision: None,
                data: json!({ "path": "nobody.toml", "trace_path": ".nobody/runs/latest.jsonl" }),
            },
            TraceEvent {
                schema_version: "nobody.trace.v1".into(),
                run_id: "run-1".into(),
                event_id: "evt-3".into(),
                parent_event_id: None,
                ts_ms: 1002,
                actor: Actor {
                    kind: "runtime".into(),
                    id: "local".into(),
                },
                kind: "process.exec.allow".into(),
                decision: Some(DecisionSummary {
                    decision: "allow".into(),
                    rule_id: Some("process.rule.allow_args".into()),
                    resource: json!({
                        "kind": "process",
                        "program": "cargo",
                        "argv": ["test"],
                    }),
                    action: "process_exec".into(),
                    matched_pattern: Some("test".into()),
                    message: "process arguments matched allow rule for cargo".into(),
                }),
                data: json!({ "program": "cargo", "argv": ["test"] }),
            },
            TraceEvent {
                schema_version: "nobody.trace.v1".into(),
                run_id: "run-1".into(),
                event_id: "evt-4".into(),
                parent_event_id: None,
                ts_ms: 1003,
                actor: Actor {
                    kind: "runtime".into(),
                    id: "local".into(),
                },
                kind: "env.filtered".into(),
                decision: None,
                data: json!({ "allowed_count": 7, "denied_count": 42 }),
            },
            TraceEvent {
                schema_version: "nobody.trace.v1".into(),
                run_id: "run-1".into(),
                event_id: "evt-5".into(),
                parent_event_id: None,
                ts_ms: 1004,
                actor: Actor {
                    kind: "runtime".into(),
                    id: "local".into(),
                },
                kind: "sandbox.prepared".into(),
                decision: None,
                data: json!({ "backend": "landlock", "enforced": true }),
            },
            TraceEvent {
                schema_version: "nobody.trace.v1".into(),
                run_id: "run-1".into(),
                event_id: "evt-6".into(),
                parent_event_id: None,
                ts_ms: 1010,
                actor: Actor {
                    kind: "runtime".into(),
                    id: "local".into(),
                },
                kind: "run.completed".into(),
                decision: None,
                data: json!({ "code": 0, "success": true }),
            },
        ];

        let out = format_events_explain(&events);

        assert!(out.contains("Command: cargo test"));
        assert!(out.contains("Policy: nobody.toml"));
        assert!(out.contains("Sandbox: backend=landlock enforced=true"));
        assert!(out.contains("Exit: code=0 success=true"));
        assert!(out.contains("process.exec ALLOW cargo test rule=process.rule.allow_args"));
        assert!(out.contains("env.filtered allowed=7 denied=42"));
    }

    #[test]
    fn reads_legacy_trace_events() {
        let legacy = r#"{"ts_ms":1760000000000,"kind":"run.start","data":{"program":"echo"}}"#;
        let legacy: LegacyTraceEvent = serde_json::from_str(legacy).unwrap();

        assert_eq!(legacy.kind, "run.start");
        assert_eq!(legacy.data["program"], "echo");
    }

    #[test]
    fn selects_latest_run_events() {
        let events = vec![
            TraceEvent {
                schema_version: "nobody.trace.v1".into(),
                run_id: "run-1".into(),
                event_id: "evt-1".into(),
                parent_event_id: None,
                ts_ms: 1000,
                actor: Actor {
                    kind: "runtime".into(),
                    id: "local".into(),
                },
                kind: "run.created".into(),
                decision: None,
                data: json!({}),
            },
            TraceEvent {
                schema_version: "nobody.trace.v1".into(),
                run_id: "run-2".into(),
                event_id: "evt-1".into(),
                parent_event_id: None,
                ts_ms: 2000,
                actor: Actor {
                    kind: "runtime".into(),
                    id: "local".into(),
                },
                kind: "run.created".into(),
                decision: None,
                data: json!({}),
            },
        ];

        let latest = latest_run_events(&events);

        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].run_id, "run-2");
    }
}
