# CLI Exit Codes

Exit codes should be predictable.

Suggested model:
- 0: execution successful, no threshold breach;
- 1: configured severity threshold reached;
- 2: invalid arguments;
- 3: input/read error;
- 4: unexpected internal error.

Documenting codes makes TraceGuard safer to integrate with pipelines.