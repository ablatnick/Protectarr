# Changelog

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
