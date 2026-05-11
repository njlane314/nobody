use crate::{
    NetworkSandboxPlan, PreparedSandbox, PreparedSandboxBackend, ResolvedSandboxSpec, SandboxSpec,
    SandboxStatus, linux_netns, reject_deny_carveouts, resolve_spec, support_read_paths,
};
use anyhow::{Context, Result, bail};
use landlock::{
    ABI, Access, AccessFs, LandlockStatus, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    path_beneath_rules,
};
use std::collections::BTreeSet;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};

#[derive(Clone)]
struct PreparedLandlockSandbox {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    network_plan: NetworkSandboxPlan,
    network_mode: String,
    warning: Option<String>,
}

pub(crate) fn prepare(spec: &SandboxSpec) -> Result<PreparedSandbox> {
    let resolved = resolve_spec(spec)?;
    let (read_paths, write_paths) = landlock_paths(resolved)?;
    let network_plan = spec.network.plan();
    let network_mode = spec.network.mode_label().into();
    let warning = match &network_plan {
        NetworkSandboxPlan::Diagnostic { warning } => Some(warning.clone()),
        NetworkSandboxPlan::Disabled | NetworkSandboxPlan::DenyAll => None,
    };

    Ok(Box::new(PreparedLandlockSandbox {
        read_paths,
        write_paths,
        network_plan,
        network_mode,
        warning,
    }))
}

impl PreparedSandboxBackend for PreparedLandlockSandbox {
    fn status(&self) -> SandboxStatus {
        let network_enforced = matches!(self.network_plan, NetworkSandboxPlan::DenyAll);
        SandboxStatus {
            backend: if network_enforced {
                "landlock+netns".into()
            } else {
                "landlock".into()
            },
            enforced: true,
            filesystem_enforced: true,
            network_enforced,
            network_mode: self.network_mode.clone(),
            warning: self.warning.clone(),
        }
    }

    fn spawn(&self, command: &mut Command) -> Result<Child> {
        let read_paths = self.read_paths.clone();
        let write_paths = self.write_paths.clone();
        let network_plan = self.network_plan.clone();

        // Install Landlock in the child after fork and before exec so the
        // parent runtime can keep writing traces and supervising the process.
        unsafe {
            command.pre_exec(move || {
                if matches!(network_plan, NetworkSandboxPlan::DenyAll) {
                    linux_netns::deny_all_network()
                        .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
                }

                enforce_landlock(&read_paths, &write_paths)
                    .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))
            });
        }

        command
            .spawn()
            .context("failed to spawn landlocked command")
    }
}

fn landlock_paths(resolved: ResolvedSandboxSpec) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut read_paths: BTreeSet<PathBuf> = support_read_paths(&resolved.working_dir)
        .into_iter()
        .collect();
    read_paths.extend(resolved.read_paths);

    let write_paths: BTreeSet<PathBuf> = resolved.write_paths.into_iter().collect();
    reject_deny_carveouts(
        &resolved.deny_paths,
        read_paths.iter().chain(write_paths.iter()),
    )?;

    Ok((
        read_paths.into_iter().collect(),
        write_paths.into_iter().collect(),
    ))
}

fn enforce_landlock(read_paths: &[PathBuf], write_paths: &[PathBuf]) -> Result<()> {
    let abi = ABI::V3;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?;

    ruleset = ruleset.add_rules(path_beneath_rules(
        read_paths.iter().map(PathBuf::as_path),
        AccessFs::from_read(abi),
    ))?;

    ruleset = ruleset.add_rules(path_beneath_rules(
        write_paths.iter().map(PathBuf::as_path),
        AccessFs::from_all(abi),
    ))?;

    let status = ruleset.restrict_self()?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {}
        RulesetStatus::PartiallyEnforced => {
            bail!("Landlock ruleset was only partially enforced");
        }
        RulesetStatus::NotEnforced => {
            bail!("Landlock ruleset was not enforced");
        }
    }

    match status.landlock {
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => {
            bail!("Landlock is not available on this Linux host");
        }
        LandlockStatus::Available { .. } => {}
    }

    Ok(())
}
