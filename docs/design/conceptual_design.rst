*****************
Conceptual Design
*****************

The conceptual design separates authority, enforcement, and evidence.  Policy
describes what a subject may do.  Enforcement mechanisms make those decisions
true where possible.  Trace events make the decisions and observed effects
auditable after the run.

===============
Authority Model
===============

The intended authority relation is a total function over policy, request, and
context:

.. code-block:: text

   eval(policy, request, context) -> decision, reason

The reason is part of the contract.  A boundary that cannot explain why a
request was allowed or denied cannot be audited by inspection.

================
Capability Graph
================

Capabilities form a graph from actor to subject to resources.  The graph should
make delegation explicit: the actor has broad authority, but the subject
receives only the subset named in policy for the current run.

=============
Run Lifecycle
=============

The run lifecycle is:

1. load policy,
2. validate and normalize policy,
3. construct an enforcement plan,
4. create trace state,
5. evaluate the subject launch request,
6. start or deny the subject,
7. record runtime events, and
8. finalize the trace summary.

======================
Enforcement Boundaries
======================

Different capabilities require different mechanisms.  Filesystem operations may
use Landlock, mount namespaces, overlays, and path policy.  Process execution
uses allow/deny checks, namespace inheritance, seccomp, and resource limits.
Network access uses a deny-default network namespace, DNS policy, and an egress
proxy.  MCP tools and secrets require mandatory user-space mediation.

==============
Approval Gates
==============

An approval gate represents a request that policy cannot automatically allow.
The runtime should suspend the request, identify the approver, record the
decision, and continue only with the approved authority.

==============
Evidence Model
==============

Evidence is not diagnostic noise.  It is the record used to inspect a run,
answer why an action happened, reconstruct authority use, and export audit
material.
