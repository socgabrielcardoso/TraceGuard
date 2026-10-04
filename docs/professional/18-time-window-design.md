# Time Window Design

Time-based rules require clear semantics.

Define:
- event-time source;
- timezone;
- inclusive/exclusive boundaries;
- behavior for out-of-order events;
- reset conditions;
- maximum retained state.

Ambiguous windows create inconsistent detections and difficult tests.