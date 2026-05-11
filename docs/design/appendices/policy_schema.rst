*************
Policy Schema
*************

The policy schema is intentionally plain.  TOML keeps the first design
reviewable in normal code review and easy to generate from other systems later.

==============
Agent and Task
==============

The agent section names the subject class.  The task section describes the work
context, such as a repository or task identifier.

======================
Filesystem and Network
======================

Filesystem policy declares readable, writable, and denied paths.  Network
policy declares the default mode and endpoint allow/deny lists.

=======================
Process and Environment
=======================

Process policy declares allowed and denied programs.  Environment policy
declares whether inherited variables are cleared and which variable names may be
kept.

===================
Approvals and Trace
===================

Approval policy names operations that must suspend for explicit approval.  Trace
policy selects the event output path and redaction patterns.
