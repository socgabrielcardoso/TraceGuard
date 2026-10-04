# Impossible or Rare Patterns

Detection should prefer evidence-backed anomalies over dramatic labels.

Examples:
- source changes faster than operationally expected;
- service account used interactively;
- dormant account becomes active;
- privileged login from uncommon source;
- repeated access outside baseline.

The engine should report the observed pattern and let the analyst determine business legitimacy.