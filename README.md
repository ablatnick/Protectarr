<img width="1254" height="1254" alt="ChatGPT Image Sep 30, 2026, 03_36_28 PM" src="https://github.com/user-attachments/assets/a87db8a0-497c-48fd-b87e-9ff9f1521b6b" />
# Protectarr

Scared to torrent due to security risks? Worry no more! Protectarr stands in between your machine and torrent files.

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

**After the download finishes, before import.** Protectarr reads each file's first bytes to find its real type, so a Windows program renamed `.mkv` is caught. It lists archives without extracting them (and flags password-protected ones), and sends every non-media file to ClamAV.

Each *arr app gets rules that fit what it downloads. Lidarr releases may contain `.cue`, `.log` and booklet PDFs, and Readarr releases may contain EPUB, PDF and audiobook files, so neither is mistaken for a fake video.

## What it does about it

| Verdict | Examples | Default action |
|---|---|---|
| **Malicious** | a program, a disguised program, a password-protected archive, a ClamAV detection | **Block:** stop the torrent, move any files into a read-only quarantine, remove it from the *arr queue with blocklisting on (so it searches for another release), and notify you |
| **Suspicious** | a WMV file, an archive, a video far too small, a file that isn't what its name says | **Hold:** stop the torrent, lock away any files so nothing imports them, and wait for you to **Allow** or **Deny** it on the Review page |
| **Clean** | a normal release | Nothing. If qBittorrent paused it after metadata, Protectarr starts it again |

You can change each action to `block`, `hold` or `alert` (tag and notify only). Notifications go anywhere [Apprise](https://github.com/caronc/apprise/wiki) supports: Discord, Telegram, ntfy, email, Pushover and more.

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

   Addresses can be `192.168.1.10:8989` or a full URL. Click **Save and test**: every service shows **Connected** or tells you what to fix, and the category table lists what's being watched. Changes apply immediately, with no restart.

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
  - on torrent added: `curl -fsS "http://your-server:9797/api/hook/added?hash=%I&key=YOUR_PASSWORD"`
  - on torrent finished: `curl -fsS "http://your-server:9797/api/hook/finished?hash=%I&key=YOUR_PASSWORD"`

  (The linuxserver.io qBittorrent image includes `curl`.)

## Web UI

`http://your-server:9797`, protected by `PROTECTARR_API_KEY` (log in with any username and that password).

- **Activity:** every check, with the reasons and the indexer.
- **Review:** held downloads waiting for Allow or Deny.
- **Quarantine:** blocked files, which you can restore or delete.
- **Indexers:** which indexers sent bad releases.
- **Settings:** the address and key of every service, their live status with setup hints, and the categories being watched.

There's a JSON API too: `/api/status`, `/api/settings` (GET, and POST to change connections from a script), `/api/events`, `/api/review`, `/api/quarantine`, `/api/indexers`, and `/health`.

## Container settings

Service connections are easiest to set on the Settings page. Everything, including the rules, can also be set with environment variables on the container, which is handy for infrastructure-as-code. Anything saved on the Settings page takes precedence over these for the service connections.

If you'd rather use a file, copy [`config.example.yml`](config.example.yml) to `/config/config.yml`: when that file exists it's used instead of the environment variables, and it can still pull secrets from the environment with `${VAR}`.

| Variable | Default | |
|---|---|---|
| `QBIT_URL` | empty | qBittorrent Web UI, e.g. `http://qbittorrent:8080`. Nothing contacts qBittorrent until this (or the Settings page) is set |
| `QBIT_USERNAME` / `QBIT_PASSWORD` | `admin` / empty | |
| `QBIT_RESUME_OTHER_CATEGORIES` | `true` | Start new torrents in other categories that qBittorrent's stop condition held (only ones added in the last 2 minutes) |
| `QBIT_CATEGORIES` | empty | Check only these categories instead of the ones read from the *arr apps |
| `<APP>_URL`, `<APP>_API_KEY` | | `<APP>` is `SONARR`, `RADARR`, `LIDARR`, `READARR` or `WHISPARR`, optionally with a suffix (`RADARR_4K_URL`) |
| `<APP>_CATEGORIES` | empty | Categories for that app, if it can't be read from its settings |
| `PROWLARR_URL`, `PROWLARR_API_KEY` | empty | |
| `CLAMAV_ENABLED` | `true` | |
| `CLAMAV_HOST` / `CLAMAV_PORT` | empty / `3310` | clamd to scan with, e.g. `clamav` or `192.168.1.10` |
| `CLAMAV_STREAM_MAX_MB` | `25` | Largest file sent to ClamAV; keep it at or below clamd's `StreamMaxLength` |
| `ACTION_MALICIOUS` / `ACTION_SUSPICIOUS` | `block` / `hold` | `block`, `hold` or `alert` |
| `MIN_EPISODE_MB` / `MIN_MOVIE_MB` | `30` / `300` | Smallest believable episode and movie |
| `CATEGORY_MIN_VIDEO_MB` | empty | Per-category override, e.g. `tv-anime=15` |
| `CATEGORY_PROFILES` | empty | What a category holds when no *arr app says so, e.g. `audiobooks=book,concerts=movie` (`tv`, `movie`, `music`, `book`) |
| `ALLOW_ARCHIVES` | `false` | Set `true` if you use Unpackerr for scene RAR releases. Archives are still checked for passwords and programs |
| `EXTRA_BLOCKED_EXTENSIONS` | empty | e.g. `.iso,.torrent` |
| `PATH_MAPPINGS` | empty | `qbit-path:protectarr-path`, comma-separated |
| `PROTECTARR_API_KEY` | empty | Web UI password; also required as `?key=` on hooks |
| `PUBLIC_URL` | empty | How you open the UI, for links in notifications |
| `APPRISE_URLS` | empty | Space-separated Apprise URLs |
| `POLL_SECONDS` | `5` | How often qBittorrent is checked |
| `QUARANTINE_DIR` / `DATA_DIR` | `/quarantine` / `/config` | |

## Known limits

- **It protects a media pipeline; it is not an antivirus.** It is built to catch fake and bait releases. It cannot make cracked software safe, and a brand-new trojan that ClamAV doesn't know yet will pass the signature check. (It will still be caught if it's a program pretending to be a video.)
- **Import race.** Sonarr/Radarr can import a finished download before the content scan runs. Protectarr polls every few seconds and the finished hook is instant, and most bait is caught from the file list before it downloads, so this is rare.
- **Large files and ClamAV.** Only files up to `CLAMAV_STREAM_MAX_MB` go to ClamAV. Big files that are verified real videos or audio are not sent; they're rarely the carrier.
- **qBittorrent only**, for now. Transmission and Deluge support is planned.
- **Keep the UI on your LAN** (or behind a VPN or reverse proxy with its own login), and set `PROTECTARR_API_KEY`. Behind a reverse proxy, set `PUBLIC_URL` to the address you open it on.
- **Failed qBittorrent logins back off** (1 minute, doubling up to 15), because qBittorrent bans an address after 5 failures. Saving the Settings page retries straight away.

## Development

```
pip install -e '.[test]'
pytest
```

`python3 e2e/run.py` starts a throwaway stack (qBittorrent, Sonarr, Lidarr, Prowlarr, ClamAV and Protectarr built from your checkout), connects everything from scratch and runs real bait scenarios against it. It needs Docker, and ClamAV takes a few minutes to get ready on the first run. Add `--down` to remove the stack afterwards.

[`docs/design.md`](docs/design.md) explains how it hooks into qBittorrent and the *arr apps, and why.

## License

[MIT](LICENSE)
