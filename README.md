<img width="750" height="750" alt="Pixel-Art Blue Shield Emblem" src="https://github.com/user-attachments/assets/8cbfd4c3-f1e1-44bd-a2c3-34ecc8d42b22" />

# Protectarr

Scared to torrent due to security risks? Worry no more (or at least worry less)! Protectarr stands in between your machine and torrent files. I can not take full credit for this creation. As my coding skills are lacking I relied on Claude for a majority of the coding. Sure I could have taken the time and coded this myself (which I have very little of due to being a college student). Although, after a recent scare in my own arr stack and suspicious files downloading onto my homelab. I felt the sooner something like this is created the better! This whole project is open source, please make changes and make your own version of this project! In a world where everything requires a subscription owning your own stuff becomes ever increasingly difficult. I hope this project helps to get homelabbing and owning your own media out there, by adding a little more security and giving people a little more peace of mind.

Protectarr stops fake and malicious torrent releases before they reach your media library. It sits beside qBittorrent and your *arr apps (Sonarr, Radarr, Lidarr, Readarr, Whisparr, with Prowlarr for indexer reports), checks every download they grab, and has the *arr app blocklist anything bad and search for a different release.

It's aimed at the fake releases that turn up on public indexers: a "new episode" that is really `Show.S01E01.mkv.exe`, a movie that's a 2 MB `.wmv` asking you to download a codec, or a password-protected archive with a "get the password here" link.

## What it catches

**Before anything downloads.** As soon as qBittorrent knows a torrent's file list, Protectarr checks names and sizes for:

- program files: `.exe`, `.scr`, `.lnk`, `.bat`, `.msi`, `.ps1`, `.js` and more
- disguised names such as `Movie.mkv.exe`, and the hidden right-to-left override character that makes a program's name display like a video's
- archives and disk images where a video or album should be
- lure files such as `password.txt`, `codec` installers and `.url` links
- WMV/ASF "codec" bait
- videos far too small for what they claim to be (an episode under 30 MB, a movie under 300 MB)

**While it downloads, and before import.** Protectarr reads each file's first bytes as soon as they arrive to find its real type, so a Windows program renamed `.mkv` is caught. It lists archives without extracting them (and flags password-protected ones), and sends every non-media file to ClamAV.

Each *arr app gets rules that fit what it downloads. Lidarr releases may contain `.cue`, `.log` and booklet PDFs, and Readarr releases may contain EPUB, PDF and audiobook files, so neither is mistaken for a fake video.

## What it does about it

| Verdict | Examples | Default action |
|---|---|---|
| **Malicious** | a program, a disguised program, a password-protected archive, a ClamAV detection | **Block:** stop the torrent, move any files into a read-only quarantine, remove it from the *arr queue with blocklisting on (so it searches for another release) |
| **Suspicious** | a WMV file, an archive, a video far too small, a file that isn't what its name says | **Hold:** stop the torrent, lock away any files so nothing imports them, and wait for you to **Allow** or **Deny** it on the Review page |
| **Clean** | a normal release | Nothing. If qBittorrent paused it after metadata, Protectarr starts it again |

You can change each action to `block` or `hold`.

## Quick start

Protectarr is a single container. You run qBittorrent (4.5 or later, 5.x recommended), your *arr apps and ClamAV however you already do, and connect them in Protectarr's web UI.

1. **Start Protectarr** with [`docker-compose.yml`](docker-compose.yml), or:

   ```
   docker run -d --name protectarr -p 9797:9797 --user 1000:1000 \
     -e PROTECTARR_API_KEY=choose-a-password \
     -v ./protectarr/config:/config -v ./protectarr/quarantine:/quarantine \
     -v /path/to/downloads:/downloads \
     ghcr.io/ablatnick/protectarr:latest
   ```

   Two things matter:
   - `--user` must match qBittorrent's `PUID:PGID`, so Protectarr can move files into quarantine.
   - Mount your downloads folder at **the same path qBittorrent uses** (for example `/downloads` or `/data`).

2. **Start ClamAV** if you don't run it already (optional, but recommended):

   ```
   docker run -d --name clamav -p 3310:3310 -v ./clamav:/var/lib/clamav clamav/clamav:stable
   ```

   It needs a few minutes to download its signatures on first start.

3. **Open `http://your-server:9797/settings`** (any username, the password you chose) and enter:
   - qBittorrent's address, username and password,
   - each *arr app's address and API key (**Settings > General > Security** in that app),
   - ClamAV's host and port (3310), and Prowlarr if you want indexer reports.

   Addresses can be `your-server-ip:8989` or a full URL. Click **Save and test**: every service shows **Connected** or tells you what to fix, and the category table lists what's being watched. Changes apply immediately, with no restart.

4. In qBittorrent, set **Options > Downloads > Torrent stop condition** to **Metadata received**. New torrents then wait until Protectarr has checked their file list, and Protectarr starts them if they pass. That setting applies to every torrent, so Protectarr also starts new torrents in categories it doesn't check; torrents you stopped yourself are never touched.

The Settings page shows a **Getting started** checklist until these steps are done.

You don't list categories anywhere: Protectarr reads them from each *arr app's qBittorrent download client, and picks up changes within 10 minutes. Torrents in other categories are left alone, and nothing is checked until at least one *arr app is connected.

On its first connection Protectarr leaves torrents that had already finished alone, and only checks new ones.

### What each connection adds

| Service | What you get |
|---|---|
| **qBittorrent** | Required. Protectarr watches it, stops bad torrents and restarts clean ones |
| **Sonarr, Radarr, Whisparr** | Their categories are checked with TV or movie rules; bad releases are blocklisted there and re-searched |
| **Lidarr** | Music rules for its category (cue sheets, rip logs and booklets are fine) |
| **Readarr** (or a fork such as Bookshelf) | Book and audiobook rules for its category |
| **A second instance** (4K, anime…) | Add it as another row and give it a name like "Radarr 4K" |
| **Prowlarr** | Links and indexer status on the **Indexers** page, which shows which indexers send bad releases |
| **ClamAV** | Signature scanning of every non-media file |

The Indexers page works without Prowlarr too: the indexer comes from the *arr app that grabbed the release.

**ClamAV** can be any clamd reachable over TCP, including one you already run. Protectarr streams files to it (`INSTREAM`), so ClamAV doesn't need to see your downloads folder. To scan bigger files, raise clamd's `StreamMaxLength` and set the size limit on the Settings page to match.

**Addresses:** use something Protectarr can reach from inside its container: the server's LAN IP and published port, or the container name if they share a Docker network (`http://sonarr:8989`). `localhost` means Protectarr's own container.

**Different paths in qBittorrent and Protectarr:** if you can't mount the downloads folder at the same path, set `PATH_MAPPINGS=/path/in/qbittorrent:/path/in/protectarr` on the container.

### Optional qBittorrent settings

- **Options > Downloads > Keep incomplete torrents in:** a separate folder, so half-finished files are never mistaken for finished ones.
- **Options > Downloads > Run external program**, so Protectarr reacts instantly instead of within a few seconds. The Settings page shows the exact commands for your setup:
  - on torrent added: `curl -fsS "http://your-server:9797/api/hook/added?hash=%I&key=YOUR_API_KEY"`
  - on torrent finished: `curl -fsS "http://your-server:9797/api/hook/finished?hash=%I&key=YOUR_API_KEY"`

  `YOUR_API_KEY` is `PROTECTARR_API_KEY`, or the generated key shown on the Settings page if you didn't set one.

  (The linuxserver.io qBittorrent image includes `curl`.)

## Recommended containers

Protectarr works alongside these. None are required except qBittorrent and at least one *arr app, but together they make a safer setup.

**Security**

| Container | Why | GitHub |
|---|---|---|
| ClamAV | Scans the files Protectarr sends it (subtitles, extras, archives) for known malware. Recommended; Protectarr only needs its TCP port (3310). Image: `clamav/clamav` | [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav) · [docker](https://github.com/Cisco-Talos/clamav-docker) |
| Gluetun | Runs qBittorrent through a VPN with a kill switch, so torrent traffic never leaves without it. Image: `qmcgaw/gluetun` | [passteque/gluetun](https://github.com/passteque/gluetun) |

**Download client**

| Container | Why | GitHub |
|---|---|---|
| qBittorrent | The torrent client Protectarr watches (4.x and 5.x). The LinuxServer.io image includes `curl` for the instant hooks | [qbittorrent/qBittorrent](https://github.com/qbittorrent/qBittorrent) · [linuxserver/docker-qbittorrent](https://github.com/linuxserver/docker-qbittorrent) |

**The *arr stack**

| Container | Why | GitHub |
|---|---|---|
| Sonarr | TV shows | [Sonarr/Sonarr](https://github.com/Sonarr/Sonarr) |
| Radarr | Movies | [Radarr/Radarr](https://github.com/Radarr/Radarr) |
| Lidarr | Music | [Lidarr/Lidarr](https://github.com/Lidarr/Lidarr) |
| Bookshelf | Books and audiobooks: a maintained fork of Readarr, which has been retired. Add it in Protectarr as type Readarr | [pennydreadful/bookshelf](https://github.com/pennydreadful/bookshelf) · [Readarr (archived)](https://github.com/Readarr/Readarr) |
| Whisparr | Adult content | [Whisparr/Whisparr](https://github.com/Whisparr/Whisparr) |
| Prowlarr | Manages indexers for all of the above; connect it to Protectarr to see which indexers send bad releases | [Prowlarr/Prowlarr](https://github.com/Prowlarr/Prowlarr) |

## Web UI

`http://your-server:9797`, protected by `PROTECTARR_API_KEY` (log in with any username and that password). After the first login you can set your own username and password under Settings > Login; from then on the API key only works for qBittorrent hooks and the JSON API, not the pages. Without `PROTECTARR_API_KEY`, setting a login protects the page and generates a key for the hooks, shown on the Settings page. Locked out? Set `PROTECTARR_RESET_LOGIN=true`, restart, log in with the API key, and remove the variable again. Repeated wrong passwords make an address wait a few minutes.

- **Activity:** every check, with the reasons and the indexer.
  <img width="1102" height="1319" alt="Screenshot From 2026-09-30 19-07-30" src="https://github.com/user-attachments/assets/db3450ca-ec87-44fb-8516-c24fc6d352b4" />
- **Review:** held downloads waiting for Allow or Deny.
  <img width="1319" height="422" alt="Screenshot From 2026-09-30 19-07-43" src="https://github.com/user-attachments/assets/be8148e0-dcdc-47a3-a43b-909b5cd78ebf" />
- **Quarantine:** blocked files, which you can restore or delete.
  <img width="1347" height="497" alt="Screenshot From 2026-09-30 19-07-53" src="https://github.com/user-attachments/assets/cd979888-0f37-44ab-91ca-d22dd0258c2b" />
- **Indexers:** which indexers sent bad releases.
  <img width="1332" height="424" alt="Screenshot From 2026-09-30 19-08-03" src="https://github.com/user-attachments/assets/b9cd48d6-bbae-46dc-9f1d-57876357ce0a" />
- **Settings:** the address and key of every service, their live status with setup hints, and the categories being watched.
  <img width="940" height="1321" alt="Screenshot From 2026-09-30 19-08-32" src="https://github.com/user-attachments/assets/8077e42f-2f62-4688-a399-b5a9bad738af" />
There's a JSON API too: `/api/status`, `/api/settings` (GET, and POST to change connections from a script), `/api/events`, `/api/review`, `/api/quarantine`, `/api/indexers`, and `/health`.

## Container settings

Service connections are easiest to set on the Settings page. Everything, including the rules, can also be set with environment variables on the container, which is handy for infrastructure-as-code. Anything saved on the Settings page takes precedence over these for the service connections.

If you'd rather use a file, copy [`config.example.yml`](config.example.yml) to `/config/config.yml`: when that file exists it's used instead of the environment variables, and it can still pull secrets from the environment with `${VAR}`.

| Variable | Default | |
|---|---|---|
| `QBIT_URL` | empty | qBittorrent Web UI, e.g. `http://qbittorrent:8080`. Nothing contacts qBittorrent until this (or the Settings page) is set |
| `QBIT_USERNAME` / `QBIT_PASSWORD` | `admin` / empty | |
| `QBIT_RESUME_AFTER_CHECK` | `true` | Start torrents that qBittorrent's stop condition held once their file list passes |
| `QBIT_RESUME_OTHER_CATEGORIES` | `true` | Start new torrents in other categories that qBittorrent's stop condition held (only ones added in the last 2 minutes, or while Protectarr was down) |
| `QBIT_CATEGORIES` | empty | Check only these categories instead of the ones read from the *arr apps |
| `<APP>_URL`, `<APP>_API_KEY` | | `<APP>` is `SONARR`, `RADARR`, `LIDARR`, `READARR` or `WHISPARR`, optionally with a suffix (`RADARR_4K_URL`) |
| `<APP>_CATEGORIES` | empty | Categories for that app, if it can't be read from its settings |
| `PROWLARR_URL`, `PROWLARR_API_KEY` | empty | |
| `CLAMAV_ENABLED` | `true` | |
| `CLAMAV_HOST` / `CLAMAV_PORT` | empty / `3310` | clamd to scan with, e.g. `clamav` or `your-server-ip` |
| `CLAMAV_TIMEOUT` | `120` | Seconds to wait for ClamAV to scan one file |
| `CLAMAV_STREAM_MAX_MB` | `25` | Largest file sent to ClamAV; keep it at or below clamd's `StreamMaxLength` |
| `CLAMAV_SCAN_MEDIA` | `false` | Also send verified real video/audio files to ClamAV (their real type is always checked). Slow for albums and season packs |
| `ACTION_MALICIOUS` / `ACTION_SUSPICIOUS` | `block` / `hold` | `block` or `hold` |
| `MIN_EPISODE_MB` / `MIN_MOVIE_MB` | `30` / `300` | Smallest believable episode and movie |
| `CATEGORY_MIN_VIDEO_MB` | empty | Per-category override, e.g. `tv-anime=15` |
| `CATEGORY_PROFILES` | empty | What a category holds when no *arr app says so, e.g. `audiobooks=book,concerts=movie` (`tv`, `movie`, `music`, `book`) |
| `ALLOW_ARCHIVES` | `false` | Set `true` if you use Unpackerr for scene RAR releases. Archives are still checked for passwords and programs |
| `EXTRA_BLOCKED_EXTENSIONS` | empty | e.g. `.iso,.torrent` |
| `PATH_MAPPINGS` | empty | `qbit-path:protectarr-path`, comma-separated |
| `PROTECTARR_API_KEY` | empty | Web UI password until you set your own login on the Settings page; also required as `?key=` on hooks |
| `PROTECTARR_RESET_LOGIN` | `false` | Forget the login set on the Settings page (when you're locked out) |
| `PUBLIC_URL` | empty | How you open the UI, if that's through a reverse proxy |
| `POLL_SECONDS` | `5` | How often qBittorrent is checked |
| `EARLY_CHECKS` | `true` | Check files while they download (real type from the first piece, full scan as each file finishes) |
| `QUARANTINE_DIR` / `DATA_DIR` | `/quarantine` / `/config` | |
| `PORT` | `9797` | Port the web UI listens on inside the container |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |
| `PROTECTARR_CONFIG` | `/config/config.yml` | Where to look for the optional config file |

## Known limits/DISCLAIMER

- **It protects a media pipeline; it is not an antivirus.** It is built to catch fake and bait releases. It cannot make cracked software safe, and a brand-new trojan that ClamAV doesn't know yet will pass the signature check. (It will still be caught if it's a program pretending to be a video.)
- **Import race.** Sonarr/Radarr import a download as soon as it finishes, so a check that runs after completion can lose that race. Protectarr closes it from both sides: while a torrent downloads it asks qBittorrent for each file's first and last pieces early, checks each file's real type as soon as its first piece arrives, and fully scans every file the moment it finishes, so there's almost nothing left to check at completion. And if an *arr app still imports something bad first (for example while Protectarr was down), Protectarr deletes the imported file through that app, marks the grab as failed so the release is blocklisted and searched again, and removes the torrent. Lidarr and Readarr are handled the same way.
- **Large files and ClamAV.** Only files up to `CLAMAV_STREAM_MAX_MB` go to ClamAV, and files that are verified real videos or audio are not sent unless `CLAMAV_SCAN_MEDIA=true`; they're rarely the carrier.
- **Nothing unchecked passes as clean.** If the downloaded files can't be found (wrong `PATH_MAPPINGS` or mounts), can't be read, or ClamAV is down, the download is treated as suspicious and held (by default) instead of passed. Downloads held only because ClamAV was down are scanned again and released or blocked automatically once it's back. The Settings page warns when qBittorrent's download folder isn't visible to Protectarr.
- **Held means held.** A held torrent that something else starts (you in qBittorrent, qbit_manage) is stopped again; use Allow on the Review page. When files can't be moved into the quarantine folder, they're renamed in place with `.protectarr-held` so no *arr app imports them.
- **Torrents keep being checked after their category changes**, for example by an *arr app's "category after import".
- **Notifications: coming soon.** Protectarr doesn't send alerts (Discord, Telegram, ntfy, email) yet. For now, check the Activity and Review pages (Review shows a badge when something is waiting for you), or watch the container log, which records every block and hold.
- **qBittorrent only**, for now. Transmission and Deluge support is planned.
- **Keep the UI on your LAN** (or behind a VPN or reverse proxy with its own login), and set `PROTECTARR_API_KEY` or your own login. Wrong passwords lock out an address for a few minutes; behind a reverse proxy that address is the proxy's, so repeated failures there make everyone wait. Behind a reverse proxy, set `PUBLIC_URL` to the address you open it on.
- **Failed qBittorrent logins back off** (1 minute, doubling up to 15), because qBittorrent bans an address after 5 failures. Saving the Settings page retries straight away.
-  **CAN FAIL** Protectarr can fail or make mistakes! Protectarr is designed to mitigate risks with torrenting. Even though this container has underwent numerous tests there is still a possibility of failure. By downloading this container you understand that this is not your antivirus solution, it is intended as just another layer to protect you. 

## Development

```
pip install -e '.[test]'
pytest
```

`python3 e2e/run.py` starts a throwaway stack (qBittorrent, Sonarr, Lidarr, Prowlarr, ClamAV and Protectarr built from your checkout), connects everything from scratch and runs real bait scenarios against it. It needs Docker, and ClamAV takes a few minutes to get ready on the first run. Add `--down` to remove the stack afterwards.

[`docs/design.md`](docs/design.md) explains how it hooks into qBittorrent and the *arr apps, and why.

## License

[MIT](LICENSE)
