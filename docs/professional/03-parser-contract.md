# Parser Contract

A parser should:
- reject malformed input predictably;
- preserve the raw line when useful;
- never invent missing security fields;
- normalize time consistently;
- expose parse errors separately from detections;
- remain deterministic for the same input.

Parser failures are telemetry quality issues, not security findings by themselves.