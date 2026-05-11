************
Threat Model
************

The design reduces the authority of a subject under a stated policy.  It is not
a proof that an arbitrary host is safe.

In scope:

* a subject attempting to run denied commands,
* a subject attempting to read or write denied paths,
* arbitrary network egress,
* unauthorized MCP tool calls,
* secret use outside approved sinks, and
* irreversible actions that require approval.

Out of scope initially:

* a compromised host kernel,
* a malicious root administrator,
* hardware side channels,
* perfect data-flow tracking through arbitrary process memory, and
* full deterministic replay of all programs.
