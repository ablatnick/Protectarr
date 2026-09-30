# Security

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button on this repository rather than in a public issue.

Protectarr stores the passwords and API keys you enter on the Settings page in its SQLite database under `/config`, the same way the *arr apps keep theirs in their config folders. Your own web UI password (Settings > Login) is stored only as a salted PBKDF2 hash. Keep that folder private, set `PROTECTARR_API_KEY` or your own login, and don't expose the web UI to the internet without a reverse proxy that adds its own login.
