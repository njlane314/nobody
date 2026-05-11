****************
Technical Design
****************

The technical design maps the authority model onto a Rust workspace.  Dependency
direction matters: policy types should not depend on Linux confinement, and
trace readers should not depend on the command-line interface.

================
Workspace Layout
================

The current workspace is split into focused crates:

``nobody-cli``
   Command parsing and terminal-facing behavior.

``nobody-policy``
   Policy structures, validation, and decision evaluation.

``nobody-runtime``
   Run lifecycle, process supervision, and environment filtering.

``nobody-trace``
   Trace event schema, JSONL writing, and compact trace display.

======================
Command-Line Interface
======================

The primary interface remains:

.. code-block:: sh

   nobody run --policy nobody.toml -- <command>

Supporting commands inspect policy and trace output without broadening the
authority granted to the subject.

=============================
Policy Parsing and Validation
=============================

The parser accepts agent, task, filesystem, network, process, environment,
approval, and trace sections.  The prototype enforces process and environment
sections first while preserving the larger file shape for future enforcement.

===================
Runtime Supervision
===================

The runtime owns run creation, preflight checks, child process launch, exit
status collection, and trace finalization.

=====================
Environment Filtering
=====================

Environment filtering prevents the subject from inheriting credentials and
machine state simply because the actor had them.  Trace events record variable
names and counts, not values.

===================
Process Enforcement
===================

Process policy is enforced before spawn.  Denied commands do not run, and the
denial is recorded in the trace.

======================
Filesystem Enforcement
======================

Filesystem enforcement is planned around Linux Landlock, mount namespaces,
overlay directories, and path-matching policy.  The prototype does not yet block
filesystem access.

===================
Network Enforcement
===================

Network policy should default to deny and route permitted egress through a
mediated path that records destination decisions.  The prototype does not yet
enforce network access.

======================
MCP and Tool Mediation
======================

Tool calls should be treated as capability-bearing operations.  A future MCP
proxy will inspect tool schemas, evaluate requests, and enforce allow, deny, or
approval decisions.

===============
Secret Handling
===============

Secrets should be brokered into approved sinks rather than inherited through the
process environment.  Trace output must avoid recording secret values.

=============
Trace Writing
=============

Trace output is newline-delimited JSON.  Each event carries schema version, run
identifier, event identifier, timestamp, actor, event kind, optional decision,
and payload data.

===============
Replay and Diff
===============

Replay initially means reconstruction of authority history, not deterministic
re-execution of arbitrary programs.  Diffing should compare what authority was
requested, granted, denied, and observed across runs.

==============
Error Handling
==============

Errors in policy validation, unavailable enforcement mechanisms, failed proxies,
or failed secret brokers must fail closed.  Failure should not widen authority.

=============
Configuration
=============

The default policy path is ``nobody.toml`` and the default trace path is
``.nobody/runs/latest.jsonl``.  Both should remain visible and easy to inspect.

================
Platform Support
================

The first strong enforcement target is Linux.  Other platforms may support
policy evaluation and trace generation before they support equivalent kernel
boundaries.
