# Changelog

## 0.4.0

- **Activity history:** the Activity page pages back through older results (100 per page, also `GET /api/events?before=<id>`). Clean results older than 90 days are removed every 6 hours; change it under Settings > Activity history (or `HISTORY_DAYS` / `history_days`, `0` keeps everything). Blocked, held and denied results are always kept, so the Indexers page counts don't change.

- **Allowed file types:** Settings > Allowed file types (or `ALLOWED_EXTENSIONS` / `rules.allowed_extensions`, or `GET`/`POST /api/rules`) lists extensions that shouldn't be flagged, for when Protectarr holds or blocks releases for a file type you're fine with. What's inside those files is still checked: a file that isn't really its extension's type, `Movie.mkv.exe`-style names, hidden right-to-left characters, lure names, password-protected archives and ClamAV detections are still caught. Allowing a program type shows a warning.

- **Logins and tokens, kept apart:** the web UI, the JSON API and the qBittorrent hooks each have their own credential, so a leaked one only opens what it's for.
  - **Web UI login:** on first start a random password for `admin` is generated and printed once in the log (or set `PROTECTARR_USERNAME`/`PROTECTARR_PASSWORD`). Change it under Settings > Login; it's stored as a salted PBKDF2 hash. There is no default password, and the UI is never open without a login.
  - **API token** (`PROTECTARR_API_KEY`, or generated): opens `/api/` only, sent as a header (`Authorization: Bearer` or `X-Api-Key`), never in a URL. It no longer opens the web pages.
  - **Hook token** (generated): opens only `/api/hook/`. The hook commands on the Settings page send it as a header, so it stays out of access logs.
  - Tokens can be regenerated on the Settings page. `PROTECTARR_RESET_LOGIN=true` replaces a forgotten login with a new generated one. After 10 wrong passwords or tokens in 5 minutes an address is refused (even with the right password) for a few minutes, and checking a password never holds up scanning.
  - Older setups keep working: a saved login, the old hook key, and hooks passing `PROTECTARR_API_KEY` as `?key=` (with a warning in the log).

- **Non-root image:** the Docker image runs as `1000:1000` by default; set `user:` to qBittorrent's `PUID:PGID` as before.

- **Logo:** the pixel-art blue shield (`docs/logo.png`) is Protectarr's logo, in the README and as the web UI's header icon and favicon.

- **Architecture diagrams:** the README has a stack diagram, and [`docs/architecture.md`](docs/architecture.md) walks through a download and the credentials.

- **Antivirus notes:** the README explains why antivirus software may flag the test files and the quarantine folder, and the test sources no longer contain the EICAR string itself.

- **Removed: Apprise notifications and the `alert` action.** Notifications are coming back as a proper feature. `APPRISE_URLS` / `apprise_urls` are ignored, and an existing `alert` action is treated as `hold` (with a warning in the log). Blocks and holds are still recorded on the Activity page and in the log.

Fixes from a stress test of every way a bad file could get through:

- **Nothing unchecked passes as clean any more.**
  - Downloaded files that can't be found (wrong path mapping or mount) used to be skipped and the download marked clean. Now it's held, with a hint to fix `PATH_MAPPINGS`, and the Settings page warns when qBittorrent's download folder isn't visible.
  - A download that couldn't be checked after 3 tries was recorded as an error and left for the *arr app to import. Now it's treated as suspicious (held by default).
  - ClamAV being down made files count as clean. Now they're held, and scanned again automatically once ClamAV answers: released if clean, blocked if infected.
  - When the quarantine folder can't be written (full disk, wrong owner), files are renamed in place (`.protectarr-held`) so nothing imports them; a half-finished move is rolled back. When blocking, the files are deleted with the torrent instead.
- **Torrents that leave the watched category are still checked**, e.g. when an *arr app's "category after import" moves them before the scan finished.
- **Held torrents stay stopped** if something else starts them.
- **Library clean-up only deletes the file the bad release imported.** A release added again after it was blocked no longer touches the library (it could delete a good file that replaced it), and a path taken over by a later import is left alone.
- **A failed removal is retried** instead of the release later being recorded as clean.
- **Scans never hold up the poll loop:** files that finish while downloading are scanned beside it, and verified media isn't sent to ClamAV unless `CLAMAV_SCAN_MEDIA=true`. A 30-track album no longer delays blocking a new bait torrent.
- **More Windows-runnable files blocked:** `.scf .chm .one .msix .appx .xll .msc .vb .ws .settingcontent-ms .library-ms .xlsm .docm .py .pyw .gadget` and more, names ending in a dot or space (`Setup.exe.`), and other right-to-left tricks besides RLO.
- With `ALLOW_ARCHIVES=true`, archives containing another archive or a disk image are suspicious.
- **Fewer false alarms:** full Blu-ray/DVD rips (BDMV, VIDEO_TS), `.tif`/`.bmp`/`.gif` scans, `.opf` in audiobooks, RF64/BW64 WAVs over 4 GB, MP3s with leading padding, and `.ts` recordings that don't start on a packet.
- A clean torrent stopped by qBittorrent just as Protectarr restarted is started after the restart, and torrents in other categories added while Protectarr was down are started too.
- Two quarantine entries can no longer share a folder (the same torrent quarantined twice in one second).
- `/api/settings` answers malformed input with 400 instead of 500, and rejects invalid ClamAV ports.

## 0.3.0

- **Import race closed from both sides.**
  - Files are checked while they download: qBittorrent is asked for each file's first and last pieces early, a file's real type is checked as soon as its first piece arrives, and each file is fully scanned (archives, ClamAV) the moment it finishes. A program disguised as a video is usually caught within seconds of the download starting, and at completion only unchecked files remain. Turn off with `EARLY_CHECKS=false`.
  - If an *arr app imported a bad download before Protectarr caught it, Protectarr now deletes the imported library file through that app, marks the grab as failed (which blocklists the release and searches again) and removes the torrent. Before, it could only delete the torrent.

## 0.2.0

- **Settings page:** enter the address and API key of qBittorrent, each *arr app, ClamAV and Prowlarr in the web UI, with live connection status and setup hints. Changes apply without a restart. Environment variables and the config file still work.
- **Whole *arr stack:** Lidarr, Readarr and Whisparr alongside Sonarr and Radarr, including several instances of one app. The qBittorrent categories to watch are read from each app's download client settings.
- **Music and book rules**, so Lidarr and Readarr releases (cue sheets, rip logs, booklets, EPUB, audiobooks) aren't mistaken for fake videos. EPUB/CBZ/CBR contents are still checked for programs.
- **Indexers page:** which indexers sent bad releases, with Prowlarr links.
- Faster content checks: a file already known to be a program is not also sent to ClamAV, and scans run beside the poll loop.
- Fixed: a clean torrent could stay stopped when qBittorrent applied "stop after metadata" just after Protectarr's check.
- Fixed: qBittorrent 5.1+ logins (HTTP 204).
- Allow/Deny/Restore/Delete refuse cross-site requests.
- Nothing is checked until an *arr app (or a category) is configured, and qBittorrent isn't contacted until its address is set.
- **Getting started checklist** on the Settings page, and a pending-count badge on Review. Tables become cards on phones.
- Failed qBittorrent logins back off instead of retrying every poll, which got Protectarr banned by qBittorrent. A ban is recognised and explained.
- New torrents in categories Protectarr doesn't check are started when qBittorrent's "stop after metadata" held them.
- Connection checks give up after 8 seconds, so a wrong IP can't hang the Settings page.
- Works behind reverse proxies (forwarded host or `PUBLIC_URL` accepted for form posts).
- A download whose files can't be read is reported on the Activity page after 3 attempts instead of being retried forever.
- Two apps with the same name are refused.
- A saved password or API key is only reused for the same address, so nobody who can open the Settings page can redirect a service to their own server to collect it.
- An address that answers with something other than the expected app (a login page, a wrong port) is reported instead of stopping all checks.
- Fewer false alarms: comics that are zips named `.cbr` (and the reverse), FLAC with an ID3 header, PDFs with bytes before the header, older `.mov` and MPEG-1 `.mpg` files.
- Activity shows when ClamAV couldn't scan a file; Allow/Deny/Restore/Delete errors are shown on the page.

## 0.1.0

- First version: file-list and content checks for qBittorrent with Sonarr/Radarr, ClamAV, quarantine, Review page and Apprise notifications.
