*******
Roadmap
*******

The implementation should move from semantics to enforcement:

1. stabilize the trace schema,
2. add policy explanation and simulation commands,
3. add filesystem decision simulation,
4. introduce a Linux sandbox crate interface,
5. enforce Landlock filesystem policy,
6. add escape tests for denied files and descendants,
7. validate Landlock in Linux CI,
8. add deny-default network mediation,
9. add MCP proxying,
10. add secret brokering, and
11. add replay and diff views.
