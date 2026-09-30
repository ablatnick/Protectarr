# Protectarr: concept and design

_Written 2026-09-30, before the first version was built. It explains the approach; the README describes what exists today._

## 1. The idea in one paragraph

Protectarr is a small service that sits beside a torrent client (qBittorrent first) and the *arr stack (Sonarr, Radarr, Lidarr, with Prowlarr supplying indexers). It watches every torrent from the moment its file list is known until the moment its content is imported into a media library, and at each step it checks for the things that malicious torrents actually do: executables dressed up as movies, fake extensions, password-protected archives with "get the password here" lures, and known-bad files. Anything suspicious is stopped, quarantined, and reported back so the *arr app blocklists that release and grabs a different one.

It is not a general antivirus and not a network proxy. Its value is that it understands torrents and the *arr workflow, which a desktop antivirus does not.

## 2. Corrections to the original write-up

The original concept has the right goal, but a few claims would lead the design astray:

| Original claim | Reality | What it means for the design |
|---|---|---|
| "qBittorrent or **Limewire**" | LimeWire was a Gnutella/P2P client and has been dead since 2010. It is not a torrent client. | Target qBittorrent first; Transmission and Deluge later. |
| "Limewire running through **Prowlarr magnet streams**" | Prowlarr is an indexer manager. It finds releases and hands them to Sonarr/Radarr; it never downloads or "streams" anything. | Prowlarr is useful only for knowing which indexer a bad release came from. |
| Scan the "incoming file stream **before** it reaches the drive" and "abort the download" | BitTorrent downloads pieces out of order, written straight into the target files. Until the torrent completes there is no whole file to scan, and a partial file mostly can't be judged. | There are two real checkpoints: the **file list** (known before any data arrives) and the **finished files** (before anything opens or imports them). See section 3. |
| The daemon "intercepts the save operation" as a man-in-the-middle | Intercepting writes needs a kernel-level filter (a Windows minifilter driver, or Linux fanotify). That is a large, risky project and still can't judge incomplete files. | Don't intercept writes. Use the client's API and hooks. Optional on-access blocking (Linux fanotify, which ClamAV's `clamonacc` already does) can come much later. |
| Blocks threats "at the moment of execution rather than after installation" | Blocking at execution is what a desktop antivirus does. Protectarr's advantage is catching the file earlier: before download, and before import. | Frame the product around "never reaches your library", not execution. |
| Heuristic/behavioral analysis of payloads | Behavioural analysis means running the file in a sandbox, which is heavy and out of scope. | Use static checks: file type vs. extension, signatures (ClamAV), rules (YARA), hash reputation. |

A realistic limit worth stating up front: Protectarr can catch fake and bait releases very well, and known malware reasonably well. It cannot make cracked software safe. A trojanized installer that no scanner has seen yet will pass. The honest pitch is "protects your media pipeline", not "makes pirated software safe".

## 3. How it hooks in

There are three checkpoints, in order of how early they act.

### 3.1 Metadata stage (before any content downloads)

As soon as a magnet link resolves its metadata, qBittorrent knows every file name and size in the torrent. This is the only point where Protectarr can truly block a file before it hits the disk, and it catches most fake releases.

- **How it learns about new torrents:** poll the qBittorrent Web API (`/api/v2/torrents/info`, `/api/v2/torrents/files`) every few seconds, and/or use qBittorrent's "Run external program on torrent added" option to ping Protectarr immediately.
- **Hold point:** qBittorrent 4.5+ has a "Torrent stop condition: Metadata received" setting, so new torrents can pause after metadata until Protectarr clears them. Without that, Protectarr acts fast enough on most torrents because metadata arrives before meaningful data.
- **What it checks:** file names and sizes against rules (section 4.1).
- **What it can do:**
  - skip just the bad files by setting their priority to 0 (`/api/v2/torrents/filePrio`), if the rest of the torrent is fine;
  - or stop and delete the whole torrent (`/api/v2/torrents/stop`, `/api/v2/torrents/delete`) and tell the *arr app to blocklist the release (section 5).

### 3.2 Completion stage (after download, before anything uses it)

When the torrent finishes, the files are complete and can be scanned properly.

- **Trigger:** qBittorrent's "Run external program on torrent finished" (it can pass `%I` hash, `%F` content path, `%L` category), calling a tiny script that notifies Protectarr. Polling for `state` changes is the fallback.
- **Staging folder:** qBittorrent's "Keep incomplete torrents in" setting means half-downloaded files live in a separate folder and only move to the real download folder when complete. That keeps the scanner away from partial files and makes "incomplete" vs. "ready to scan" a simple folder distinction.
- **What it checks:** real file type, embedded executables, archives, ClamAV, YARA, hash reputation (section 4).
- **Folder watching** (inotify on Linux, with a polling fallback for network shares and Docker bind mounts where inotify is unreliable) is a secondary option for clients Protectarr has no API integration for yet.

### 3.3 Import stage (the *arr apps)

Sonarr and Radarr poll the download client and import completed downloads on their own schedule. That creates a race: if Sonarr imports before Protectarr finishes scanning, the bad file is already in the library.

Options, from simplest to strictest:

1. **Fast scan plus cleanup (MVP).** Most bait is caught at the metadata stage, and a completion scan of a normal release takes seconds. If something is found after import, Protectarr quarantines the imported file too and records it.
2. **Remove and blocklist through the *arr API.** When Protectarr rejects a download, it calls the Sonarr/Radarr queue API (`DELETE /api/v3/queue/{id}?removeFromClient=true&blocklist=true`). The *arr app then blocklists that release and searches for another. This is the key piece that turns "blocked" into "automatically replaced".
3. **Strict gate (later).** Hold torrents where the *arr app can't import them until they are cleared, for example by withholding a category or tag. This needs testing against how Sonarr/Radarr track downloads by hash and category, so it's an open question rather than an MVP feature.

The *arr "Custom Script" connection (On Grab, On Import) is useful for logging and for mapping a torrent back to its indexer, but On Import fires after the import, so it can't block anything on its own.

Worth noting: recent Sonarr/Radarr versions already warn about some executable files in downloads, and community tools such as Cleanuparr and Decluttarr offer extension blocklists and cleanup of bad downloads. Protectarr should check what those do today and aim to go further (content scanning, archive inspection, quarantine, reporting) rather than duplicate them.

## 4. Scanning

Checks run cheapest first, and most torrents are cleared by the first two.

### 4.1 Name and size rules (metadata stage, instant)

- Dangerous extensions in a media release: `.exe .scr .com .bat .cmd .ps1 .vbs .js .jse .wsf .hta .msi .lnk .pif .jar .dll`, and on macOS/Linux `.app .dmg .pkg .sh .desktop`.
- Double extensions such as `Movie.2026.1080p.mkv.exe`, and the Unicode right-to-left override character (U+202E), which hides the real extension.
- Archives (`.zip .rar .7z`) or disk images (`.iso .img`) in a release that should just be a video or audio file.
- Size that doesn't fit the claim, such as a "4K movie" of a few megabytes.
- `.wmv`/`.asf` files in modern releases, an old "download this codec to play" lure.
- Files named like `password.txt`, `codec.exe`, `README_to_play.url` and similar.

### 4.2 Real file type (completion stage, fast)

Read the first bytes of each file with libmagic and compare against the extension. A `.mkv` should start with the EBML header and an `.mp4` with an `ftyp` box. An `MZ` (Windows executable), ELF, Mach-O, ZIP or script header inside something named as media is a strong signal. This is the "fake extension" check and it costs almost nothing.

### 4.3 Archives

List contents without extracting. Flag executables inside, nested archives, and above all **password-protected archives in media releases**, which are nearly always a scam. For clean-looking archives, pass contents to ClamAV, which already unpacks common formats.

### 4.4 ClamAV (signatures)

Run `clamd` as a sidecar container, keep it updated with `freshclam`, and stream files to it over its socket (`INSTREAM`) or scan by path if both containers share the volume. Good at known malware; weaker on brand-new samples. Large video files are slow to scan and rarely the carrier, so scan executables, archives, documents and anything that failed the type check in full, and apply a size cap or sampling to verified media files.

### 4.5 YARA (custom rules)

YARA rules let Protectarr describe patterns ClamAV doesn't cover: known bait templates, lure text in bundled `.txt`/`.url` files, suspicious installers. Ship a small curated rule set, allow users to add their own, and optionally pull public rule sets.

### 4.6 VirusTotal (hash reputation, optional)

Look up the SHA-256 of executables and archives only. Two rules:

- **Never upload files automatically.** Uploading shares the file publicly with VirusTotal's partners, which is a privacy problem.
- The free public API is rate-limited (4 lookups a minute, 500 a day) and is for non-commercial use only. Treat it as an optional user-supplied key with a local cache. MalwareBazaar is a free alternative for hash lookups.

### 4.7 Verdicts

Each file gets **clean**, **suspicious** or **malicious**, with the reasons. A torrent's verdict is its worst file. Users choose per verdict whether to quarantine, skip the file, or only alert. Sensible default: malicious means quarantine and blocklist; suspicious means quarantine and alert.

## 5. Quarantine and blocking

- **Quarantine folder** outside the media library, e.g. `/quarantine/<date>/<hash>/`. Files are moved (not copied), made non-executable and read-only, and stored alongside a small JSON record: torrent name, hash, indexer, file paths, verdict, reasons, scanner versions.
- **Torrent handling:** stop and remove the torrent. Default to deleting its data too, because the files already sit in quarantine.
- **Feed back to the *arr app:** remove from queue with `blocklist=true` so it searches for another release (section 3.3).
- **Release-level blocklist:** keep a local record of bad info-hashes and release names so the same torrent re-added from another indexer is refused at the metadata stage.
- **Restore and delete:** a user can release a false positive back to the download folder (and remove it from the blocklist) or delete it permanently from the UI.
- **Alerts:** Discord/Telegram/email via Apprise, plus a webhook, so it plugs into existing homelab notifications.
- **Audit log:** every decision recorded in SQLite and viewable in the UI.

## 6. Suggested MVP

Goal: catch the common fake and bait releases for a Docker-based qBittorrent plus Sonarr/Radarr setup, and get them automatically replaced.

In scope:

1. qBittorrent integration via Web API polling plus the "on added" and "on finished" hooks.
2. Metadata-stage name and size rules, with file skipping or torrent removal.
3. Completion-stage file-type check, archive listing (including password detection), and ClamAV scan.
4. Quarantine folder with JSON records and restore/delete.
5. Sonarr and Radarr queue removal with blocklisting.
6. A minimal web UI: recent verdicts, quarantine list, settings. Plus Apprise notifications.
7. One Docker Compose file with Protectarr and ClamAV.

Out of scope for the MVP: YARA, VirusTotal, other torrent clients, a strict import gate, on-access (fanotify) blocking, Windows service packaging, and any sandbox or behavioural analysis.

## 7. Tech stack

Most *arr users run Docker on Linux, Unraid or a NAS, so Protectarr should ship as a container first.

- **Language:** Python 3.12+. It has the best libraries for every piece: `qbittorrent-api`, `python-magic` (libmagic), `yara-python`, a small clamd socket client, `apprise`, and `httpx` for the *arr APIs. Go is a reasonable alternative for a single static binary, but its YARA and libmagic bindings need cgo and the ecosystem is thinner.
- **Service:** FastAPI for the web UI, hook endpoints and REST API; an asyncio worker for polling and a scan queue.
- **Storage:** SQLite for verdicts, blocklist and audit log.
- **Scanner:** the official `clamav/clamav` container as a sidecar, sharing the downloads volume read-only.
- **UI:** server-rendered pages with htmx to start; the *arr-style React UI can come later if it earns its place.
- **Config:** a YAML file plus environment variables, following the *arr conventions (API keys, URLs, `PUID`/`PGID`).

Rough flow:

```
Prowlarr -> Sonarr/Radarr -> qBittorrent
                                 |  (on added / metadata)
                                 v
                           Protectarr: name/size rules --reject--> skip files or remove + blocklist
                                 |  (on finished)
                                 v
                           Protectarr: type check, archives, ClamAV
                                 |-- clean ---------> Sonarr/Radarr import as normal
                                 '-- bad -----------> quarantine + remove + blocklist in *arr + alert
```

## 8. Decisions and open questions

Decided 2026-09-30: target Docker setups first, since the main worry is fake movies and shows carrying malware. The first version is built on that basis (see the README).

Decided 2026-09-30: suspicious downloads are held automatically and the user is notified, then chooses Allow or Deny on a Review page. Malicious ones are removed without asking.

Still open:

1. Do you want the strict import gate (section 3.3, option 3) investigated early, or is "fast scan plus automatic replacement" good enough to start?
