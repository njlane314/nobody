*******
Roadmap
*******

The implementation should move from semantics to enforcement:

1. 0.3: Linux filesystem enforcement,
2. 0.4: escape-test suite,
3. 0.5: process and environment hardening,
4. 0.6: trace viewer and policy diagnostics polish,
5. 0.7: network egress enforcement,
6. 0.8: agent profiles,
7. 0.9: MCP proxy, and
8. 1.0: stable local agent runtime.

The immediate post-Landlock priority is the escape suite, not network.  The
tests should prove that allowed interpreters and build systems remain unable to
read denied files.
