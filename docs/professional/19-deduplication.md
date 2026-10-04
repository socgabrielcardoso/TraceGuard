# Incident Deduplication

Repeated evidence may generate alert floods.

Deduplication keys can combine rule, account, source and time bucket.

Do not deduplicate so aggressively that separate attacks collapse into one incident. Preserve count and first/last seen metadata.