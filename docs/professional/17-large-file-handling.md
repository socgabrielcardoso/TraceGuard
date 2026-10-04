# Large File Handling

Prefer streaming over loading an entire log file when practical.

Benefits:
- predictable memory use;
- easier handling of large datasets;
- earlier detection output;
- lower crash risk.

If ordering matters, document that assumption explicitly.