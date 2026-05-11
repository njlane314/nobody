use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use nobody_policy::{Action, ActionKind, Decision, DecisionReason, Policy, Resource};
use nobody_runtime::{RunSpec, Runtime};
use nobody_trace::{format_events, format_events_jsonl, latest_run_events, read_events};
use std::path::PathBuf;

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
    Run(RunArgs),
    Policy(PolicyArgs),
    Trace(TraceArgs),
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
}

#[derive(Debug, Args)]
struct TraceShowArgs {
    #[arg(long)]
    jsonl: bool,

    #[arg(default_value = "latest")]
    target: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => run(args),
        Command::Policy(args) => policy(args),
        Command::Trace(args) => trace(args),
    }
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

fn policy(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Check(args) => {
            let loaded = Policy::load(&args.policy)?;
            println!(
                "policy ok: {} (trace: {})",
                args.policy.display(),
                loaded.trace_path().display()
            );
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
            let path = match args.target.as_str() {
                "latest" => PathBuf::from(".nobody/runs/latest.jsonl"),
                other => PathBuf::from(other),
            };

            let events = read_events(&path)
                .with_context(|| format!("failed to read trace: {}", path.display()))?;

            if events.is_empty() {
                bail!("trace is empty: {}", path.display());
            }

            let shown = if args.target == "latest" {
                latest_run_events(&events)
            } else {
                events
            };

            if args.jsonl {
                print!("{}", format_events_jsonl(&shown)?);
            } else {
                print!("{}", format_events(&shown));
            }
            Ok(())
        }
    }
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
    }
}
