**********
Deployment
**********

The core runtime is a local binary.  A hosted service can distribute policy,
store approvals, summarize traces, integrate identity, and export evidence, but
the boundary should remain enforceable without a hosted control plane.

The first deployment targets are developer workstations and CI runners.  Managed
runners can use the same policy and trace model once the local primitive is
stable.
