# Architecture

TraceGuard follows a defensive pipeline: input logs → parsing → normalization → rule evaluation → incident classification → output.

## Goals
- deterministic processing;
- explainable detections;
- testable rules;
- clear separation of parsing and detection;
- machine-readable output.

New features should preserve this separation so investigation logic remains auditable.