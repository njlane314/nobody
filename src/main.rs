use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use nobody::policy;
use nobody::trace;
use serde_json::json;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

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
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(short, long, default_value = "nobody.toml")]
    policy: PathBuf,

    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => run(args),
    }
}

fn run(args: RunArgs) -> Result<()> {
    let policy = policy::Policy::load(&args.policy)?;

    let program = args.command.first().context("missing command to run")?;

    let argv = &args.command[1..];

    if !policy.command_allowed(program) {
        bail!("command denied by policy: {program}");
    }

    let trace_path = policy.trace_path();
    let mut trace = trace::Trace::open(&trace_path)?;

    trace.event(
        "run.start",
        json!({
            "program": program,
            "argv": argv,
            "policy": args.policy,
        }),
    )?;

    let status = ProcessCommand::new(program)
        .args(argv)
        .status()
        .with_context(|| format!("failed to start command: {program}"))?;

    trace.event(
        "run.exit",
        json!({
            "code": status.code(),
            "success": status.success(),
        }),
    )?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}
