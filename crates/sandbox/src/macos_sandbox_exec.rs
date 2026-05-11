use crate::{
    NetworkSandboxPlan, PreparedSandbox, PreparedSandboxBackend, ResolvedSandboxSpec, SandboxSpec,
    SandboxStatus, resolve_spec_allowing_deny_carveouts,
};
use anyhow::Result;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::io;
use std::os::raw::{c_char, c_ulonglong};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

#[derive(Clone)]
struct PreparedMacSandbox {
    profile: CString,
    network_plan: NetworkSandboxPlan,
    network_mode: String,
    warning: Option<String>,
}

unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: c_ulonglong, errorbuf: *mut *mut c_char) -> i32;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

pub(crate) fn prepare(spec: &SandboxSpec) -> Result<PreparedSandbox> {
    let resolved = resolve_spec_allowing_deny_carveouts(spec)?;
    let profile = CString::new(render_profile(&resolved, &spec.network))?;
    let network_plan = spec.network.plan();
    let network_mode = spec.network.mode_label().into();
    let warning = match &network_plan {
        NetworkSandboxPlan::Diagnostic { warning } => Some(warning.clone()),
        NetworkSandboxPlan::Disabled | NetworkSandboxPlan::DenyAll => None,
    };

    Ok(Box::new(PreparedMacSandbox {
        profile,
        network_plan,
        network_mode,
        warning,
    }))
}

impl PreparedSandboxBackend for PreparedMacSandbox {
    fn status(&self) -> SandboxStatus {
        let network_enforced = matches!(self.network_plan, NetworkSandboxPlan::DenyAll);
        SandboxStatus {
            backend: if network_enforced {
                "sandbox-exec+network".into()
            } else {
                "sandbox-exec".into()
            },
            enforced: true,
            filesystem_enforced: true,
            network_enforced,
            network_mode: self.network_mode.clone(),
            warning: self.warning.clone(),
        }
    }

    fn spawn(&self, command: &mut Command) -> Result<Child> {
        let profile = self.profile.clone();

        // Apply the Seatbelt profile in the child after fork and before exec,
        // preserving the runtime's environment filtering and stdio setup.
        unsafe {
            command.pre_exec(move || apply_profile(&profile));
        }

        command
            .spawn()
            .map_err(anyhow::Error::from)
            .map_err(|error| error.context("failed to spawn sandboxed command"))
    }
}

fn render_profile(spec: &ResolvedSandboxSpec, network: &crate::NetworkSandboxSpec) -> String {
    let mut read_paths: BTreeSet<PathBuf> = macos_support_read_paths().into_iter().collect();
    read_paths.extend(spec.read_paths.iter().cloned());
    read_paths.extend(spec.write_paths.iter().cloned());
    let metadata_paths = metadata_paths(spec, &read_paths);

    let mut profile = String::from(
        r#"(version 1)
(import "system.sb")
(deny default)
(allow process*)
"#,
    );

    push_path_rule(&mut profile, "allow", "file-read-metadata", &metadata_paths);
    push_path_rule(&mut profile, "allow", "file-read*", &read_paths);
    push_path_rule(&mut profile, "allow", "file-write*", &spec.write_paths);
    push_path_rule(&mut profile, "deny", "file-read*", &spec.deny_paths);
    push_path_rule(&mut profile, "deny", "file-write*", &spec.deny_paths);

    match network.plan() {
        NetworkSandboxPlan::DenyAll => {
            profile.push_str("(deny network*)\n");
        }
        NetworkSandboxPlan::Disabled | NetworkSandboxPlan::Diagnostic { .. } => {
            profile.push_str("(allow network*)\n");
        }
    }

    profile
}

fn metadata_paths(spec: &ResolvedSandboxSpec, read_paths: &BTreeSet<PathBuf>) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    for path in read_paths
        .iter()
        .chain(spec.write_paths.iter())
        .chain(spec.deny_paths.iter())
        .chain(std::iter::once(&spec.working_dir))
    {
        insert_ancestors(&mut paths, path);
    }
    paths
}

fn insert_ancestors(paths: &mut BTreeSet<PathBuf>, path: &Path) {
    let mut current = path;
    while let Some(parent) = current.parent() {
        if parent.as_os_str().is_empty() {
            break;
        }
        paths.insert(parent.to_path_buf());
        current = parent;
    }
}

fn macos_support_read_paths() -> Vec<PathBuf> {
    [
        "/var/select",
        "/private/var/select",
        "/Library/Developer/CommandLineTools",
        "/Applications/Xcode.app",
    ]
    .into_iter()
    .filter_map(|path| std::fs::canonicalize(path).ok())
    .collect()
}

fn push_path_rule(
    profile: &mut String,
    decision: &str,
    operation: &str,
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
) {
    let filters = paths
        .into_iter()
        .map(|path| path_filter(path.as_ref()))
        .collect::<Vec<_>>();

    if filters.is_empty() {
        return;
    }

    profile.push('(');
    profile.push_str(decision);
    profile.push(' ');
    profile.push_str(operation);
    for filter in filters {
        profile.push(' ');
        profile.push_str(&filter);
    }
    profile.push_str(")\n");
}

fn path_filter(path: &Path) -> String {
    let escaped = escape_scheme_string(&path.display().to_string());
    if path.is_dir() {
        format!("(subpath \"{escaped}\")")
    } else {
        format!("(literal \"{escaped}\")")
    }
}

fn escape_scheme_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn apply_profile(profile: &CString) -> io::Result<()> {
    let mut errorbuf: *mut c_char = std::ptr::null_mut();
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut errorbuf) };
    if rc == 0 {
        return Ok(());
    }

    let message = if errorbuf.is_null() {
        "sandbox_init failed".into()
    } else {
        let message = unsafe { CStr::from_ptr(errorbuf) }
            .to_string_lossy()
            .into_owned();
        unsafe {
            sandbox_free_error(errorbuf);
        }
        message
    };

    Err(io::Error::other(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkSandboxSpec, SandboxSpec};

    #[test]
    fn profile_allows_carveout_denies() {
        let tmp =
            std::env::temp_dir().join(format!("nobody-macos-profile-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(tmp.join(".env"), "secret").unwrap();

        let spec = ResolvedSandboxSpec {
            working_dir: tmp.clone(),
            read_paths: vec![tmp.clone()],
            write_paths: vec![tmp.join("src")],
            deny_paths: vec![tmp.join(".env")],
        };

        let profile = render_profile(&spec, &NetworkSandboxSpec::default());

        assert!(profile.contains("(import \"system.sb\")"));
        assert!(profile.contains(&format!("(subpath \"{}\")", tmp.display())));
        assert!(profile.contains(&format!(
            "(allow file-write* (subpath \"{}\")",
            tmp.join("src").display()
        )));
        assert!(profile.contains(&format!(
            "(deny file-read* (literal \"{}\")",
            tmp.join(".env").display()
        )));
        assert!(profile.contains("(allow network*)"));

        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn deny_all_network_profile_denies_network() {
        let spec = ResolvedSandboxSpec {
            working_dir: PathBuf::from("/repo"),
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            deny_paths: Vec::new(),
        };
        let network = NetworkSandboxSpec {
            deny: vec!["*".into()],
            ..Default::default()
        };

        let profile = render_profile(&spec, &network);

        assert!(profile.contains("(deny network*)"));
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn prepare_accepts_deny_carveouts() {
        let tmp =
            std::env::temp_dir().join(format!("nobody-macos-sandbox-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join(".env"), "secret").unwrap();

        let spec = SandboxSpec {
            working_dir: tmp.clone(),
            fs_read: vec![PathBuf::from(".")],
            fs_write: Vec::new(),
            fs_deny: vec![PathBuf::from(".env")],
            network: NetworkSandboxSpec::default(),
        };

        let prepared = prepare(&spec).unwrap();
        assert_eq!(prepared.status().backend, "sandbox-exec");

        let _ = std::fs::remove_dir_all(tmp);
    }
}
