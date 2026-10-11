# Threat model and security acceptance criteria

**Scope:** TraceGuard is a defensive, local Java CLI that reads untrusted authentication logs, normalizes events, applies detection rules and writes text/JSON findings. This document defines *verification work*, not evidence that the controls have already passed.

## Assets and trust boundaries

- **Input boundary:** logs, filenames, directory trees, timestamps, IP addresses and user identifiers are untrusted, even when supplied by an operator.
- **Execution boundary:** the Java process inherits local filesystem privileges. No parsed log field should ever become a shell command, executable path or network destination.
- **Output boundary:** JSON/text output may be consumed by terminals, CI systems and downstream processors. Treat output as untrusted data; encode each format appropriately.
- **Availability boundary:** attackers can generate extremely large, malformed or repetitive log streams to exhaust CPU, heap or disk.
- **Privacy boundary:** logs can contain usernames, hostnames and internal addresses. Avoid printing raw sensitive values beyond the minimum necessary and never commit production logs.

## Adversary and abuse cases

| Risk | Required safeguard | Acceptance test |
| --- | --- | --- |
| Maliciously crafted or oversized log line | Explicit per-line limits, safe parse failure, bounded memory | Long input is rejected or skipped with a deterministic diagnostic; process stays responsive |
| Recursive traversal and symlinks | Restrict traversal to explicitly selected files; define symlink behavior | Symlink and directory traversal fixtures cannot escape intended input scope |
| Terminal escape/control sequences in log data | Escape or strip dangerous control characters in human-readable output | ANSI/control-sequence fixture cannot alter terminal display |
| JSON injection / malformed output | Use a structured JSON serializer rather than concatenating untrusted strings | Quotes, Unicode and newlines always produce parseable JSON |
| Output overwriting arbitrary files | Explicit output target and safe error handling; avoid unintended overwrite | Existing output file behavior is documented and tested |
| Unbounded event accumulation | Streaming or explicit caps; bounded outputs and clear exit statuses | Large synthetic log completes within defined memory/time budgets |
| Inaccurate detection or severity | Reproducible fixtures, false-positive and false-negative cases | Unit tests map every rule to positive, negative and malformed fixtures |
| Sensitive log disclosure | Synthetic samples, no secrets in fixtures, redacted diagnostics | Secret scan and fixture review show no real identifiers or credentials |
| Supply-chain compromise | Locked/controlled plugin and library versions, dependency review and CI | Dependency inventory and build workflow are reproducible |

## Implementation priorities

1. **P0:** inspect parsers, file/directory handling and output serialization against the above cases; add regression tests before declaring mitigation.
2. **P0:** enforce resource limits and document behavior for invalid data and failing exports.
3. **P1:** add automated Java tests, static analysis, dependency monitoring and minimal CI permissions.
4. **P1:** document supported Java version, reproducible build commands and expected failure exit codes.
5. **P2:** provide a small set of anonymized attack fixtures and detection-quality metrics.

## Security release gate

Before merging a change that touches input handling, rules or output, capture: exact commit SHA; dependency review; test command and result; malicious-input test outcome; known residual risks; reviewer approval. A green workflow is supporting evidence, **not** proof of complete security.

**Operational rule:** use only owned/authorized logs and synthetic examples. Do not ingest corporate or third-party records into public issue discussions or commits.
