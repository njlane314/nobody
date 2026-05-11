use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
use std::process::{Child, Command};

#[cfg(any(target_os = "linux", test))]
use anyhow::{Context, bail};
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", test))]
use std::env;
#[cfg(any(target_os = "linux", test))]
use std::path::{Component, Path};

#[cfg(target_os = "linux")]
mod linux_landlock;
#[cfg(target_os = "linux")]
mod linux_netns;
mod noop;

pub use noop::NoopSandbox;

#[derive(Debug, Clone)]
pub struct SandboxSpec {
    pub working_dir: PathBuf,
    pub fs_read: Vec<PathBuf>,
    pub fs_write: Vec<PathBuf>,
    pub fs_deny: Vec<PathBuf>,
    pub network: NetworkSandboxSpec,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkSandboxSpec {
    pub mode: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkSandboxPlan {
    Disabled,
    DenyAll,
    Diagnostic { warning: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct SandboxStatus {
    pub backend: String,
    pub enforced: bool,
    pub filesystem_enforced: bool,
    pub network_enforced: bool,
    pub network_mode: String,
    pub warning: Option<String>,
}

pub type PreparedSandbox = Box<dyn PreparedSandboxBackend>;

pub trait Sandbox {
    fn prepare(&self, spec: &SandboxSpec) -> Result<PreparedSandbox>;
}

pub trait PreparedSandboxBackend {
    fn status(&self) -> SandboxStatus;
    fn spawn(&self, command: &mut Command) -> Result<Child>;
}

pub struct LinuxLandlockSandbox;

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(test, allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct ResolvedSandboxSpec {
    pub working_dir: PathBuf,
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub deny_paths: Vec<PathBuf>,
}

impl SandboxSpec {
    pub fn from_policy_paths(
        working_dir: impl Into<PathBuf>,
        fs_read: &[String],
        fs_write: &[String],
        fs_deny: &[String],
    ) -> Self {
        Self {
            working_dir: working_dir.into(),
            fs_read: fs_read.iter().map(PathBuf::from).collect(),
            fs_write: fs_write.iter().map(PathBuf::from).collect(),
            fs_deny: fs_deny.iter().map(PathBuf::from).collect(),
            network: NetworkSandboxSpec::default(),
        }
    }

    pub fn from_policy_parts(
        working_dir: impl Into<PathBuf>,
        fs_read: &[String],
        fs_write: &[String],
        fs_deny: &[String],
        net_mode: Option<String>,
        net_allow: &[String],
        net_deny: &[String],
    ) -> Self {
        Self {
            working_dir: working_dir.into(),
            fs_read: fs_read.iter().map(PathBuf::from).collect(),
            fs_write: fs_write.iter().map(PathBuf::from).collect(),
            fs_deny: fs_deny.iter().map(PathBuf::from).collect(),
            network: NetworkSandboxSpec {
                mode: net_mode,
                allow: net_allow.to_vec(),
                deny: net_deny.to_vec(),
            },
        }
    }
}

impl NetworkSandboxSpec {
    pub fn plan(&self) -> NetworkSandboxPlan {
        if self.deny.iter().any(|pattern| pattern == "*") {
            return NetworkSandboxPlan::DenyAll;
        }

        let deny_by_default = self.mode.as_deref() == Some("deny-by-default");

        if deny_by_default {
            return NetworkSandboxPlan::Diagnostic {
                warning: "network deny-by-default policy is diagnostic unless deny = [\"*\"] requests deny-all namespace enforcement".into(),
            };
        }

        if !self.deny.is_empty() {
            return NetworkSandboxPlan::Diagnostic {
                warning: "network deny lists are diagnostic unless deny = [\"*\"] requests deny-all namespace enforcement".into(),
            };
        }

        NetworkSandboxPlan::Disabled
    }

    pub fn mode_label(&self) -> &'static str {
        match self.plan() {
            NetworkSandboxPlan::Disabled => "disabled",
            NetworkSandboxPlan::DenyAll => "deny-all",
            NetworkSandboxPlan::Diagnostic { .. } => "diagnostic",
        }
    }
}

impl Sandbox for LinuxLandlockSandbox {
    fn prepare(&self, spec: &SandboxSpec) -> Result<PreparedSandbox> {
        #[cfg(target_os = "linux")]
        {
            linux_landlock::prepare(spec)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = spec;
            NoopSandbox::new(
                "Landlock filesystem enforcement is only available on Linux; filesystem policy is diagnostic only",
            )
            .prepare(spec)
        }
    }
}

pub fn platform_default_sandbox() -> Box<dyn Sandbox> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxLandlockSandbox)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Box::new(NoopSandbox::new(
            "Landlock filesystem enforcement is only available on Linux; filesystem policy is diagnostic only",
        ))
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn resolve_spec(spec: &SandboxSpec) -> Result<ResolvedSandboxSpec> {
    let cwd = absolutize_existing_dir(&spec.working_dir)
        .with_context(|| format!("invalid working directory: {}", spec.working_dir.display()))?;

    let read_paths = resolve_existing_paths(&cwd, &spec.fs_read, "fs.read")?;
    let write_paths = resolve_existing_paths(&cwd, &spec.fs_write, "fs.write")?;
    let deny_paths = resolve_policy_paths(&cwd, &spec.fs_deny);

    reject_deny_carveouts(&deny_paths, read_paths.iter().chain(write_paths.iter()))?;

    Ok(ResolvedSandboxSpec {
        working_dir: cwd,
        read_paths,
        write_paths,
        deny_paths,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn support_read_paths(working_dir: &Path) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();

    if let Some(path_var) = env::var_os("PATH") {
        for path in env::split_paths(&path_var) {
            insert_support_path(&mut paths, path, working_dir);
        }
    }

    for path in [
        "/bin",
        "/sbin",
        "/usr",
        "/usr/bin",
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/etc",
        "/dev/null",
        "/dev/zero",
        "/dev/urandom",
    ] {
        insert_existing(&mut paths, PathBuf::from(path));
    }

    paths.into_iter().collect()
}

#[cfg(target_os = "linux")]
fn insert_existing(paths: &mut BTreeSet<PathBuf>, path: impl Into<PathBuf>) {
    let path = path.into();
    if let Ok(path) = absolutize_existing(&path) {
        paths.insert(path);
    }
}

#[cfg(target_os = "linux")]
fn insert_support_path(paths: &mut BTreeSet<PathBuf>, path: PathBuf, working_dir: &Path) {
    if !path.is_absolute() {
        return;
    }

    if let Ok(path) = absolutize_existing(&path) {
        if !path.starts_with(working_dir) {
            paths.insert(path);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn resolve_existing_paths(cwd: &Path, raw_paths: &[PathBuf], label: &str) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();

    for path in raw_paths {
        let resolved = resolve_policy_path(cwd, path);
        let existing = absolutize_existing(&resolved)
            .with_context(|| format!("{label} path does not exist: {}", path.display()))?;
        paths.insert(existing);
    }

    Ok(paths.into_iter().collect())
}

#[cfg(any(target_os = "linux", test))]
fn resolve_policy_paths(cwd: &Path, raw_paths: &[PathBuf]) -> Vec<PathBuf> {
    raw_paths
        .iter()
        .map(|path| normalize_path(&resolve_policy_path(cwd, path)))
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn resolve_policy_path(cwd: &Path, path: &Path) -> PathBuf {
    let expanded = expand_tilde(path).unwrap_or_else(|| path.to_path_buf());
    if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    }
}

#[cfg(any(target_os = "linux", test))]
fn expand_tilde(path: &Path) -> Option<PathBuf> {
    let raw = path.to_string_lossy();
    let rest = raw.strip_prefix("~/")?;
    let home = env::var_os("HOME")?;
    Some(PathBuf::from(home).join(rest))
}

#[cfg(any(target_os = "linux", test))]
fn absolutize_existing_dir(path: &Path) -> Result<PathBuf> {
    let path = absolutize_existing(path)?;
    if !path.is_dir() {
        bail!("not a directory: {}", path.display());
    }
    Ok(path)
}

#[cfg(any(target_os = "linux", test))]
fn absolutize_existing(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("path does not exist: {}", path.display()))
}

#[cfg(any(target_os = "linux", test))]
fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

#[cfg(any(target_os = "linux", test))]
fn path_contains(root: &Path, child: &Path) -> bool {
    child == root || child.starts_with(root)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn reject_deny_carveouts<'a>(
    deny_paths: &[PathBuf],
    allow_paths: impl Iterator<Item = &'a PathBuf>,
) -> Result<()> {
    let allow_paths: Vec<&PathBuf> = allow_paths.collect();

    for deny in deny_paths {
        for allow in &allow_paths {
            if path_contains(allow, deny) {
                bail!(
                    "cannot enforce fs.deny {} under granted path {}; Landlock cannot express deny carve-outs beneath allowed roots",
                    display_path(deny),
                    display_path(allow)
                );
            }
        }
    }

    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn display_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_reports_not_enforced() {
        let spec = SandboxSpec {
            working_dir: PathBuf::from("."),
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            fs_deny: Vec::new(),
            network: NetworkSandboxSpec::default(),
        };
        let prepared = NoopSandbox::default().prepare(&spec).unwrap();
        let status = prepared.status();

        assert_eq!(status.backend, "noop");
        assert!(!status.enforced);
        assert!(status.warning.unwrap().contains("noop"));
    }

    #[test]
    fn detects_unenforceable_deny_carveout() {
        let tmp = env::temp_dir().join(format!("nobody-sandbox-test-{}", std::process::id()));
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

        let error = resolve_spec(&spec).unwrap_err().to_string();
        assert!(error.contains("cannot enforce fs.deny"));

        let _ = std::fs::remove_dir_all(tmp);
    }
}
