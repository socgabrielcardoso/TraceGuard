# Validation

## Build and tests

Run:

```bash
mvn clean test
mvn clean package
```

## CLI smoke tests

Exercise representative commands against synthetic log samples:

```bash
java -jar target/traceguard.jar analyze samples
java -jar target/traceguard.jar rules
```

Validate both text and JSON output when those modes are affected.

## Detection checks

Each rule change should include or preserve test coverage for:
- a positive match;
- a non-match;
- malformed or incomplete input when relevant;
- severity and output formatting.

## Acceptance criteria

Findings must be deterministic and explainable from the input event. Parser failures should not silently become false security conclusions.
