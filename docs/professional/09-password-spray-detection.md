# Password Spray Detection

Password spraying differs from brute force by distributing attempts across many accounts.

Detection signals:
- one source;
- many distinct usernames;
- low attempts per user;
- common time window;
- repeated authentication failures.

Correlating distinct-account count is more useful than only total failures.