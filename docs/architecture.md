# How Protectarr fits into your stack

GitHub draws the diagrams below. The README covers setup; [`design.md`](design.md) explains why it's built this way.

## The stack

Protectarr is one container beside the ones you already run. qBittorrent downloads and the *arr apps import as usual; Protectarr watches them through their APIs and steps in only when a file is bad. The table below lists every connection it uses.

```mermaid
flowchart LR
    ARR["Sonarr · Radarr<br/>Lidarr · Readarr"] -- grabs --> QB["qBittorrent"]
    QB -- downloads --> P["<b>Protectarr</b><br/>checks every file"]
    P -- "clean: imported" --> LIB[("Media library")]
    P -- bad --> Q[("Quarantine")]
    P -. "blocklist + search again" .-> ARR
    P <-. scans .-> CL["ClamAV"]
```

| Connection | What Protectarr uses it for |
|---|---|
| qBittorrent Web API | New torrents and their file lists (polled every few seconds), stopping, starting and removing torrents, asking for each file's first and last pieces early |
| qBittorrent hooks (optional) | An instant nudge when a torrent is added or finishes, instead of waiting for the next poll |
| Downloads folder | Reading each file's first bytes for its real type, listing archives, moving bad files to quarantine. Mounted at the same path as in qBittorrent |
| ClamAV (clamd over TCP) | Signature scans. Files are streamed to it, so ClamAV doesn't need the downloads folder |
| *arr APIs | Which categories to watch, removing a bad release from the queue with blocklisting on (the app then searches for another), deleting a bad file that was already imported |
| Prowlarr API (optional) | Indexer names and links for the Indexers page |

## What happens to a download

```mermaid
flowchart TD
    A["*arr app sends a torrent<br/>to qBittorrent"] --> B{"1. File list<br/>(before any data)"}
    B -- "program, disguised name,<br/>archive, lure file" --> BLOCK
    B -- "looks fine" --> C["Start the download<br/>(qBittorrent paused it at<br/>'Metadata received')"]
    C --> D{"2. While downloading:<br/>real type from each<br/>file's first piece"}
    D -- "a program pretending<br/>to be a video" --> BLOCK
    D -- ok --> E{"3. Each finished file:<br/>real type, archive contents,<br/>ClamAV"}
    E -- malicious --> BLOCK
    E -- suspicious --> HOLD["<b>Hold</b><br/>torrent stopped, files locked away,<br/>waits on the Review page"]
    E -- clean --> IMPORT["*arr app imports it"]
    HOLD -- Allow --> IMPORT
    HOLD -- Deny --> BLOCK
    BLOCK["<b>Block</b><br/>torrent stopped, files to quarantine,<br/>removed from the *arr queue with blocklisting,<br/>*arr searches for another release"]
    IMPORT -. "found bad after an import race<br/>(e.g. Protectarr was down)" .-> CLEAN["Delete the imported file via the *arr app,<br/>mark the grab failed (blocklist + search again)"]
```

Anything Protectarr can't check counts as suspicious, not clean: files it can't find or read, or ClamAV being down. Downloads held only because ClamAV was down are scanned again once it's back.

## Who can open what

```mermaid
flowchart LR
    U(["Web UI login<br/>username + password"]) --> PAGES["Pages<br/>(Activity, Review, Settings…)"]
    U --> API["JSON API<br/>/api/…"]
    U --> HOOKS["Hooks<br/>/api/hook/…"]
    T(["API token<br/>header only"]) --> API
    T --> HOOKS
    H(["Hook token<br/>header or ?key="]) --> HOOKS
```

The hook token lives in qBittorrent's settings and can end up in its logs, so it opens nothing but the hooks. The API token can change settings, so it's only accepted as a header (never in a URL). Neither opens the web pages.
