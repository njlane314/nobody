use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use nobody_policy::{
    Action, ActionKind, Decision, DecisionReason, DiagnosticLevel, Policy, Resource,
};
use nobody_runtime::{RunSpec, Runtime};
use nobody_sandbox::{SandboxSpec, platform_default_sandbox};
use nobody_trace::{
    TraceEvent, format_events, format_events_explain, format_events_jsonl, latest_run_events,
    read_events,
};
use std::fs;
use std::path::PathBuf;

mod mcp;
mod profiles;

#[derive(Debug, Parser)]
#[command(
    name = "nobody",
    version,
    about = "Run programs with explicit capabilities"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Doctor(DoctorArgs),
    Init(InitArgs),
    Mcp(McpArgs),
    Run(RunArgs),
    Policy(PolicyArgs),
    Trace(TraceArgs),
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(short, long, default_value = "nobody.toml")]
    policy: PathBuf,
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long)]
    profile: Option<String>,

    #[arg(short, long, default_value = "nobody.toml")]
    output: PathBuf,

    #[arg(long)]
    force: bool,

    #[arg(long)]
    list_profiles: bool,
}

#[derive(Debug, Args)]
struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    Proxy(McpProxyArgs),
}

#[derive(Debug, Args)]
struct McpProxyArgs {
    server: String,

    #[arg(short, long, default_value = "nobody.toml")]
    policy: PathBuf,

    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(short, long, default_value = "nobody.toml")]
    policy: PathBuf,

    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Check(PolicyCheckArgs),
    Simulate(PolicySimulateArgs),
}

#[derive(Debug, Args)]
struct PolicyCheckArgs {
    #[arg(default_value = "nobody.toml")]
    policy: PathBuf,
}

#[derive(Debug, Args)]
struct PolicySimulateArgs {
    #[arg(default_value = "nobody.toml")]
    policy: PathBuf,

    #[arg(last = true, required = true)]
    action: Vec<String>,
}

#[derive(Debug, Args)]
struct TraceArgs {
    #[command(subcommand)]
    command: TraceCommand,
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    Show(TraceShowArgs),
    Explain(TraceExplainArgs),
}

#[derive(Debug, Args)]
struct TraceShowArgs {
    #[arg(long)]
    jsonl: bool,

    #[arg(default_value = "latest")]
    target: String,
}

#[derive(Debug, Args)]
struct TraceExplainArgs {
    #[arg(default_value = "latest")]
    target: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Doctor(args) => doctor(args),
        Command::Init(args) => init(args),
        Command::Mcp(args) => mcp_command(args),
        Command::Run(args) => run(args),
        Command::Policy(args) => policy(args),
        Command::Trace(args) => trace(args),
    }
}

fn doctor(args: DoctorArgs) -> Result<()> {
    let policy = Policy::load(&args.policy)?;
    let diagnostics = policy.diagnostics();

    println!("nobody doctor");
    println!("os: {}", std::env::consts::OS);
    println!("policy: {} ok", args.policy.display());
    println!("trace: {}", policy.trace_path().display());
    println!();
    println!("runtime:");
    println!("  process allow: {}", list_or_none(&policy.process.allow));
    println!("  process deny: {}", list_or_none(&policy.process.deny));
    println!("  process rules: {}", process_rules_or_none(&policy));
    println!("  environment clear: {}", policy.env.clear);
    println!("  environment allow: {}", list_or_none(&policy.env.allow));
    println!("  environment deny: {}", list_or_none(&policy.env.deny));
    println!("  mcp servers: {}", mcp_servers_or_none(&policy));
    println!("  mcp scope: proxy-only; only traffic routed through nobody mcp proxy is mediated");
    println!();
    println!("sandbox:");

    let sandbox_spec = SandboxSpec::from_policy_parts(
        std::env::current_dir().context("failed to resolve current directory")?,
        &policy.fs.read,
        &policy.fs.write,
        &policy.fs.deny,
        policy.net.mode.clone(),
        &policy.net.allow,
        &policy.net.deny,
    );
    let sandbox = platform_default_sandbox();
    let sandbox_status = sandbox
        .prepare(&sandbox_spec)
        .map(|prepared| prepared.status());

    match &sandbox_status {
        Ok(status) => {
            println!("  backend: {}", status.backend);
            println!("  enforced: {}", status.enforced);
            println!(
                "  filesystem: {}",
                enforcement_label(status.filesystem_enforced)
            );
            println!(
                "  network: {} ({})",
                enforcement_label(status.network_enforced),
                status.network_mode
            );
            if let Some(warning) = &status.warning {
                println!("  warning: {warning}");
            }
        }
        Err(error) => {
            println!("  error: {error}");
        }
    }

    if diagnostics.is_empty() {
        println!();
        println!("policy warnings: none");
    } else {
        println!();
        println!("policy warnings:");
        for diagnostic in &diagnostics {
            let level = match diagnostic.level {
                DiagnosticLevel::Warning => "warning",
            };
            println!("  {level}[{}]: {}", diagnostic.code, diagnostic.message);
        }
    }

    println!();
    println!("limits:");
    println!("  network host allowlists: diagnostic");
    println!(
        "  network deny-all: {}",
        network_deny_all_label(&sandbox_status)
    );
    println!("  mcp: proxy-only");
    println!("  browser: not enforced");
    println!("  approvals: fail-closed when requested");

    println!();
    if sandbox_status.is_ok() {
        let sandbox_warning = sandbox_status
            .as_ref()
            .ok()
            .and_then(|status| status.warning.as_ref())
            .is_some();
        if diagnostics.is_empty() && !sandbox_warning {
            println!("status: ok");
        } else {
            println!("status: warnings");
        }
        Ok(())
    } else {
        println!("status: error");
        bail!("runtime doctor failed")
    }
}

fn init(args: InitArgs) -> Result<()> {
    if args.list_profiles {
        for profile in profiles::summaries() {
            println!("{:<22} {}", profile.name, profile.description);
        }
        return Ok(());
    }

    if args.output.exists() && !args.force {
        bail!(
            "refusing to overwrite {}; pass --force to replace it",
            args.output.display()
        );
    }

    let cwd = std::env::current_dir().context("failed to resolve current directory")?;
    let profile_name = args
        .profile
        .as_deref()
        .unwrap_or_else(|| profiles::detect(&cwd));
    let rendered = profiles::render(profile_name, &cwd)?;

    if let Some(parent) = args
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory: {}", parent.display()))?;
    }

    fs::write(&args.output, rendered.policy)
        .with_context(|| format!("failed to write policy: {}", args.output.display()))?;

    println!("wrote {}", args.output.display());
    println!("profile: {}", rendered.name);
    println!("description: {}", rendered.description);

    Ok(())
}

fn run(args: RunArgs) -> Result<()> {
    let policy = Policy::load(&args.policy)?;
    let trace_path = policy.trace_path();
    let mut runtime = Runtime::new(policy, trace_path)?;
    let result = runtime.run(RunSpec {
        command: args.command,
        policy_path: args.policy,
    })?;

    if !result.success {
        std::process::exit(result.code.unwrap_or(1));
    }

    Ok(())
}

fn mcp_command(args: McpArgs) -> Result<()> {
    match args.command {
        McpCommand::Proxy(args) => mcp::proxy(mcp::ProxySpec {
            server: args.server,
            policy_path: args.policy,
            command: args.command,
        }),
    }
}

fn policy(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Check(args) => {
            let loaded = Policy::load(&args.policy)?;
            print_policy_check(&args.policy, &loaded);
            Ok(())
        }
        PolicyCommand::Simulate(args) => {
            let loaded = Policy::load(&args.policy)?;
            let action = parse_action(&args.action)?;
            let decision = loaded.evaluator().evaluate(action);
            print_decision(&decision);
            Ok(())
        }
    }
}

fn trace(args: TraceArgs) -> Result<()> {
    match args.command {
        TraceCommand::Show(args) => {
            let shown = load_trace_events(&args.target)?;

            if args.jsonl {
                print!("{}", format_events_jsonl(&shown)?);
            } else {
                print!("{}", format_events(&shown));
            }
            Ok(())
        }
        TraceCommand::Explain(args) => {
            let shown = load_trace_events(&args.target)?;
            print!("{}", format_events_explain(&shown));
            Ok(())
        }
    }
}

fn load_trace_events(target: &str) -> Result<Vec<TraceEvent>> {
    let path = match target {
        "latest" => PathBuf::from(".nobody/runs/latest.jsonl"),
        other => PathBuf::from(other),
    };

    let events =
        read_events(&path).with_context(|| format!("failed to read trace: {}", path.display()))?;

    if events.is_empty() {
        bail!("trace is empty: {}", path.display());
    }

    Ok(if target == "latest" {
        latest_run_events(&events)
    } else {
        events
    })
}

fn parse_action(parts: &[String]) -> Result<Action> {
    let kind = parts.first().context("missing action kind")?;

    match kind.as_str() {
        "process.exec" => {
            let program = parts.get(1).context("process.exec requires a program")?;
            Ok(Action::ExecuteProcess {
                program: program.clone(),
                argv: parts[2..].to_vec(),
            })
        }
        "env.read" => {
            let name = parts.get(1).context("env.read requires a variable name")?;
            Ok(Action::ReadEnv { name: name.clone() })
        }
        "fs.read" => {
            let path = parts.get(1).context("fs.read requires a path")?;
            Ok(Action::ReadFile {
                path: PathBuf::from(path),
            })
        }
        "fs.write" => {
            let path = parts.get(1).context("fs.write requires a path")?;
            Ok(Action::WriteFile {
                path: PathBuf::from(path),
            })
        }
        "net.connect" => {
            let endpoint = parts.get(1).context("net.connect requires host:port")?;
            let (host, port) = parse_endpoint(endpoint)?;
            Ok(Action::ConnectNetwork { host, port })
        }
        "mcp.tool" => {
            let server = parts.get(1).context("mcp.tool requires a server name")?;
            let tool = parts.get(2).context("mcp.tool requires a tool name")?;
            Ok(Action::CallMcpTool {
                server: server.clone(),
                tool: tool.clone(),
            })
        }
        other => bail!("unknown action kind: {other}"),
    }
}

fn parse_endpoint(raw: &str) -> Result<(String, u16)> {
    let Some((host, port)) = raw.rsplit_once(':') else {
        bail!("net.connect endpoint must be host:port");
    };
    let port = port
        .parse()
        .with_context(|| format!("invalid network port: {port}"))?;
    Ok((host.into(), port))
}

fn print_decision(decision: &Decision) {
    let reason = decision.reason();

    println!(
        "{} {} {}",
        decision.kind().to_string().to_uppercase(),
        action_label(reason),
        resource_label(reason)
    );

    if let Some(rule_id) = &reason.rule_id {
        println!("rule: {rule_id}");
    }

    if let Some(pattern) = &reason.matched_pattern {
        println!("matched: {pattern}");
    }

    println!("reason: {}", reason.message);

    if matches!(reason.resource, Resource::File { .. }) {
        println!(
            "note: filesystem decisions are diagnostic; run enforcement depends on the active sandbox backend"
        );
    }

    if matches!(reason.resource, Resource::Network { .. }) {
        println!(
            "note: network host allowlists are diagnostic; deny = [\"*\"] is the current egress enforcement primitive"
        );
    }

    if matches!(reason.resource, Resource::McpTool { .. }) {
        println!(
            "note: MCP tool decisions are enforced only for traffic routed through nobody mcp proxy"
        );
    }
}

fn print_policy_check(path: &std::path::Path, policy: &Policy) {
    println!("policy ok: {}", path.display());
    println!("trace: {}", policy.trace_path().display());
    println!();
    println!("process:");
    println!("  allow: {}", list_or_none(&policy.process.allow));
    println!("  deny: {}", list_or_none(&policy.process.deny));
    println!("  rules: {}", process_rules_or_none(policy));
    println!("filesystem:");
    println!("  read: {}", list_or_none(&policy.fs.read));
    println!("  write: {}", list_or_none(&policy.fs.write));
    println!("  deny: {}", list_or_none(&policy.fs.deny));
    println!("network:");
    println!(
        "  mode: {}",
        policy.net.mode.as_deref().unwrap_or("(unspecified)")
    );
    println!("  allow: {}", list_or_none(&policy.net.allow));
    println!("  deny: {}", list_or_none(&policy.net.deny));
    println!("environment:");
    println!("  clear: {}", policy.env.clear);
    println!("  allow: {}", list_or_none(&policy.env.allow));
    println!("  deny: {}", list_or_none(&policy.env.deny));
    println!("mcp:");
    println!("  servers: {}", mcp_servers_or_none(policy));

    let diagnostics = policy.diagnostics();
    if diagnostics.is_empty() {
        println!();
        println!("warnings: none");
    } else {
        println!();
        println!("warnings:");
        for diagnostic in diagnostics {
            let level = match diagnostic.level {
                DiagnosticLevel::Warning => "warning",
            };
            println!("  {level}[{}]: {}", diagnostic.code, diagnostic.message);
        }
    }
}

fn mcp_servers_or_none(policy: &Policy) -> String {
    if policy.mcp.servers.is_empty() {
        return "(none)".into();
    }

    policy
        .mcp
        .servers
        .iter()
        .map(|(name, server)| {
            format!(
                "{} allow=[{}] deny=[{}] rules={}",
                name,
                list_or_none(&server.allow_tools),
                list_or_none(&server.deny_tools),
                server.rule.len()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn enforcement_label(enforced: bool) -> &'static str {
    if enforced { "enforced" } else { "diagnostic" }
}

fn network_deny_all_label(status: &Result<nobody_sandbox::SandboxStatus, anyhow::Error>) -> String {
    match status {
        Ok(status) if status.network_enforced => "enforced".into(),
        Ok(status) if status.network_mode == "deny-all" => "unavailable".into(),
        Ok(_) => "available with net.deny = [\"*\"]".into(),
        Err(_) => "unknown".into(),
    }
}

fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".into()
    } else {
        values.join(", ")
    }
}

fn process_rules_or_none(policy: &Policy) -> String {
    if policy.process.rule.is_empty() {
        return "(none)".into();
    }

    policy
        .process
        .rule
        .iter()
        .map(|rule| {
            let mut parts = vec![rule.program.clone()];
            if !rule.allow_args.is_empty() {
                parts.push(format!("allow_args=[{}]", rule.allow_args.join(", ")));
            }
            if !rule.deny_args.is_empty() {
                parts.push(format!("deny_args=[{}]", rule.deny_args.join(", ")));
            }
            if let Some(decision) = rule.decision {
                parts.push(format!("decision={decision:?}").to_lowercase());
            }
            parts.join(" ")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn action_label(reason: &DecisionReason) -> &'static str {
    match &reason.resource {
        Resource::Process { .. } => "process.exec",
        Resource::File { .. } => match reason.action {
            ActionKind::FsRead => "fs.read",
            ActionKind::FsWrite => "fs.write",
            _ => "fs",
        },
        Resource::Network { .. } => "net.connect",
        Resource::Env { .. } => "env.read",
        Resource::McpTool { .. } => "mcp.tool",
    }
}

fn resource_label(reason: &DecisionReason) -> String {
    match &reason.resource {
        Resource::Process { program, argv } => {
            if argv.is_empty() {
                program.clone()
            } else {
                format!("{} {}", program, argv.join(" "))
            }
        }
        Resource::File { path } => path.display().to_string(),
        Resource::Network { host, port } => format!("{host}:{port}"),
        Resource::Env { name } => name.clone(),
        Resource::McpTool { server, tool } => format!("{server}/{tool}"),
    }
}
