use anyhow::{Result, bail};
use std::io;

pub(crate) fn deny_all_network() -> Result<()> {
    let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNET;

    // A fresh network namespace has no route to the host network. This is a
    // deny-all primitive; host allowlists need a later proxy/namespace bridge.
    let rc = unsafe { libc::unshare(flags) };
    if rc != 0 {
        let error = io::Error::last_os_error();
        bail!("failed to create deny-all network namespace: {error}");
    }

    Ok(())
}
