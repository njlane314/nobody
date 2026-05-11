************
Introduction
************

``nobody`` treats each run as an authority-bearing object.  A run starts with an
actor, a subject, and a policy.  The runtime evaluates the policy, applies the
available enforcement mechanisms, starts the subject only when the boundary is
valid, and records the resulting events as trace evidence.

The current prototype is intentionally small.  It parses typed policy from
``nobody.toml``, evaluates process and environment rules, filters inherited
environment variables, runs allowed commands, and writes JSONL trace events.

=========================
Ambient Authority Problem
=========================

A developer shell commonly has broad access to source trees, credentials,
package registries, local sockets, browsers, and internal networks.  A normal
child process inherits too much of that authority by default.

Autonomous software makes that failure mode sharper.  An agent can inspect,
plan, retry, call tools, and combine local and remote actions.  The design goal
is therefore not just to log what happened, but to reduce what the subject can
do in the first place.

============
Design Goals
============

The runtime should:

* make authority explicit in a reviewable policy file,
* evaluate requests as allow, deny, or ask decisions,
* enforce the strongest boundary available for each capability class,
* record enough evidence to explain every material decision, and
* keep the main interface small enough to compose with normal Unix tools.

=================
Current Prototype
=================

The current repository enforces process allow/deny decisions before spawn and
filters inherited environment variables before the child process starts.
Filesystem, network, MCP, browser, secret, and approval boundaries are parsed
as design-facing policy sections but are not yet enforced by the runtime.

==============================
Guide to Reading This Document
==============================

This outline separates the design into four chapters.  The introduction states
the problem and current implementation status.  The high-level abstractions
define the vocabulary used by the design.  The conceptual design describes the
authority model independent of implementation.  The technical design maps that
model onto the Rust workspace and future enforcement mechanisms.
