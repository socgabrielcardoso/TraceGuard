# Brute Force Detection

A basic brute-force rule should consider count, time window, source and account.

Avoid static thresholds without context. Service accounts, scanners and broken clients can create benign repetition.

A mature rule should emit count, window, entities and reason for classification.