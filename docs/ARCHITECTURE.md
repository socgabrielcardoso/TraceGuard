# Architecture

## Overview

TraceGuard is a defensive CLI pipeline that turns authentication logs into normalized events and prioritized incidents.

## Processing pipeline

1. **Input**
   - Authentication logs are read from files or directories.

2. **Parsing**
   - Supported formats are converted into structured event objects.

3. **Normalization**
   - Fields are mapped into a consistent internal representation.

4. **Detection**
   - Rules evaluate normalized events for suspicious patterns.

5. **Prioritization**
   - Findings are classified by severity and converted into incident output.

6. **Output**
   - Human-readable and JSON formats support manual review and automation.

## Design principles

- deterministic rule behavior;
- explainable findings;
- separation between parsing and detection;
- machine-readable output;
- testable components.

## Extension points

New parsers can support additional telemetry sources, while new detection rules can expand coverage without changing the CLI contract.
