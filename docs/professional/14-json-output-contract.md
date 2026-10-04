# JSON Output Contract

Machine-readable output should use stable field names and explicit values.

Recommended fields:
- ruleId;
- title;
- severity;
- timestamp;
- entities;
- evidence;
- source;
- message.

Breaking schema changes should be documented because automation may depend on them.