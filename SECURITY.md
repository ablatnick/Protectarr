# Security

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button on this repository rather than in a public issue.

Protectarr stores the passwords and API keys you enter on the Settings page in its SQLite database under `/config`, the same way the *arr apps keep theirs in their config folders. Your own web UI password (Settings > Login) is stored only as a salted PBKDF2 hash. Keep that folder private, set `PROTECTARR_API_KEY` or your own login (without either, the password is the public default `password123`), and don't expose the web UI to the internet without a reverse proxy that adds its own login.

## Antivirus warnings

Windows Defender and other antivirus software may flag files in this repository or in Protectarr's quarantine folder. The tests use the harmless EICAR test string and fake program headers on purpose, and the quarantine folder holds downloads Protectarr blocked. Neither means Protectarr itself is malicious; see "Antivirus warnings" in the README. If your antivirus flags the Docker image itself (which contains no test files), please report it.
