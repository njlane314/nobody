************************
High-Level Abstractions
************************

The design uses a small vocabulary so that policy, runtime behavior, and trace
evidence can be inspected together.

==========================
Actors, Subjects, and Runs
==========================

An *actor* is the human, CI job, service account, or organization principal that
starts work.  A *subject* is the command, process tree, agent, MCP server, or
tool being executed.  A *run* is the bounded execution that joins the actor,
subject, policy, confinement plan, trace, and final result.

============
Capabilities
============

A *capability* is a typed grant of authority over a resource or operation.  A
grant to read a path is not a grant to write it.  A grant to call one MCP tool
is not a grant to call another.  A grant to use a secret is scoped to an
approved sink.

========
Policies
========

A policy is the source of declared authority for a run.  The first policy format
is TOML because it is easy to review, diff, and keep in a repository.  The
runtime should reject invalid policy rather than widening authority.

=========
Decisions
=========

Policy evaluation returns a decision and a reason.  The decision is one of
``allow``, ``deny``, or ``ask``.  The reason identifies the matched rule,
matched pattern, target resource, and operation.

======
Traces
======

A trace is append-only evidence for a run.  It records what was requested, which
decision was made, why that decision was made, and what effect followed.
