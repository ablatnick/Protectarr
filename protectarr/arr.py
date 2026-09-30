"""Sonarr/Radarr/Lidarr/Readarr/Whisparr: find which qBittorrent categories they use, and remove and
blocklist rejected downloads. Prowlarr: list indexers so bad releases can be traced to their source."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

import httpx

from .config import ArrConfig, ProwlarrConfig

log = logging.getLogger(__name__)
# Every *arr app ignores the query parameters it doesn't know, so one set covers them all.
UNKNOWN_ITEMS = {"includeUnknownSeriesItems": "true", "includeUnknownMovieItems": "true",
                 "includeUnknownArtistItems": "true", "includeUnknownAuthorItems": "true"}


# Where each app keeps the files it imported: (list endpoint, the history field to filter it by, delete endpoint).
LIBRARY_FILES = {
    "sonarr": ("/episodefile", "seriesId", "/episodefile"),
    "radarr": ("/moviefile", "movieId", "/moviefile"),
    "whisparr": ("/moviefile", "movieId", "/moviefile"),
    "lidarr": ("/trackfile", "albumId", "/trackfile"),
    "readarr": ("/bookfile", "bookId", "/bookfile"),
}


@dataclass
class Removal:
    app: str
    indexer: str = ""
    # Set when the app had already imported the download: the library files it deleted.
    imported: bool = False
    library_removed: list[str] = field(default_factory=list)
    library_errors: list[str] = field(default_factory=list)
    # Paths a later, different import has taken over since: not this release's file any more.
    library_kept: list[str] = field(default_factory=list)

    def describe(self) -> str:
        if not self.imported:
            return f"removed and blocklisted in {self.app}"
        text = f"{self.app} had already imported it: "
        if self.library_removed:
            text += f"deleted {len(self.library_removed)} imported file(s), "
        if self.library_errors:
            text += "COULD NOT delete " + ", ".join(self.library_errors) + " (remove by hand), "
        if self.library_kept:
            text += "left " + ", ".join(self.library_kept) + " alone (a later import replaced it), "
        return text + "marked the grab failed so it's blocklisted and searched again"


class ArrClient:
    def __init__(self, cfg: ArrConfig, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        self.name = cfg.name
        self.http = httpx.AsyncClient(base_url=cfg.url.rstrip("/") + f"/api/{cfg.api_version}", timeout=30,
                                      transport=transport, headers={"X-Api-Key": cfg.api_key})

    async def close(self) -> None:
        await self.http.aclose()

    async def status(self) -> dict:
        r = await self.http.get("/system/status")
        r.raise_for_status()
        return r.json()

    async def qbit_categories(self) -> list[str]:
        """The categories this app's enabled qBittorrent download clients put torrents in."""
        r = await self.http.get("/downloadclient")
        r.raise_for_status()
        cats = []
        for client in r.json():
            if client.get("implementation", "").lower() != "qbittorrent" or not client.get("enable", True):
                continue
            for f in client.get("fields", []):
                # tvCategory, movieCategory, musicCategory, ...; not the "move after import" ones.
                name = f.get("name", "")
                if name.endswith("Category") and "Imported" not in name and f.get("value"):
                    cats.append(str(f["value"]))
        return sorted(set(cats))

    async def find_queue_item(self, torrent_hash: str) -> dict | None:
        page = 1
        while True:
            r = await self.http.get("/queue", params={"page": page, "pageSize": 200, **UNKNOWN_ITEMS})
            r.raise_for_status()
            body = r.json()
            for item in body.get("records", []):
                if (item.get("downloadId") or "").lower() == torrent_hash.lower():
                    return item
            if page * body.get("pageSize", 200) >= body.get("totalRecords", 0):
                return None
            page += 1

    async def remove_and_blocklist(self, queue_id: int) -> None:
        r = await self.http.delete(f"/queue/{queue_id}", params={"removeFromClient": "true", "blocklist": "true"})
        r.raise_for_status()

    async def history_for(self, torrent_hash: str) -> list[dict]:
        """This app's history entries for a download (grabbed, imported, ...), newest first."""
        r = await self.http.get("/history", params={"downloadId": torrent_hash.upper(), "pageSize": 100, "page": 1,
                                                   "sortKey": "date", "sortDirection": "descending"})
        r.raise_for_status()
        body = r.json()
        records = body.get("records", body) if isinstance(body, dict) else body
        return [h for h in records if (h.get("downloadId") or "").lower() == torrent_hash.lower()]

    async def mark_failed(self, history_id: int) -> None:
        """What "Mark as failed" does in the app's History page: blocklist the release and search again."""
        r = await self.http.post(f"/history/failed/{history_id}")
        r.raise_for_status()

    async def delete_imported(self, record: dict) -> str:
        """Delete the library file an import history entry points at. Returns its path."""
        path = (record.get("data") or {}).get("importedPath") or ""
        list_path, key, delete_path = LIBRARY_FILES[self.cfg.kind]
        if not path or record.get(key) is None:
            raise LookupError("the history entry doesn't say where the file went")
        r = await self.http.get(list_path, params={key: record[key]})
        r.raise_for_status()
        match = [f for f in r.json() if f.get("path") == path]
        if not match:
            raise LookupError(f"'{path}' is no longer in the library")
        # The same path may since hold a different, good release (a later grab named the same way): only
        # delete the file this import put there.
        match = [f for f in match if _same_import(record.get("date"), f.get("dateAdded"))]
        if not match:
            raise ReplacedSince(path)
        for f in match:
            d = await self.http.delete(f"{delete_path}/{f['id']}")
            d.raise_for_status()
        return path


IMPORT_MATCH_SECONDS = 600


class ReplacedSince(LookupError):
    """The imported path now holds a file from a later import."""


def _same_import(event_date: str | None, added: str | None) -> bool:
    """Was a library file added by the import recorded at event_date? Unknown dates count as a match."""
    try:
        a, b = (datetime.fromisoformat(str(x).replace("Z", "+00:00")) for x in (event_date, added))
        return abs((a - b).total_seconds()) <= IMPORT_MATCH_SECONDS
    except (TypeError, ValueError):
        return event_date is None or added is None


async def find_owner(clients: list[ArrClient], torrent_hash: str) -> tuple[ArrClient, dict] | None:
    """The *arr app that grabbed this torrent, and its queue entry."""
    for c in clients:
        try:
            item = await c.find_queue_item(torrent_hash)
            if item:
                return c, item
        except Exception as exc:  # one broken app mustn't stop the block
            log.warning("%s: queue lookup failed: %s", c.name, exc)
    return None


async def blocklist_everywhere(clients: list[ArrClient], torrent_hash: str, history: bool = True) -> Removal | None:
    """Remove the download from whichever *arr app grabbed it, which blocklists the release there.

    While the download is in the app's queue, removing it from the queue does everything. Once the app has
    imported it, it's no longer in the queue: then the imported library files are deleted through the app,
    and the grab is marked failed, which blocklists the release and searches for another.

    history=False skips that second part: for a release that was already dealt with once and is back."""
    owner = await find_owner(clients, torrent_hash)
    if owner:
        client, item = owner
        try:
            await client.remove_and_blocklist(item["id"])
            return Removal(client.name, item.get("indexer") or "")
        except Exception as exc:
            log.warning("%s: queue removal failed: %s", client.name, exc)
    if not history:
        return None
    for c in clients:
        try:
            history = await c.history_for(torrent_hash)
        except Exception as exc:
            log.warning("%s: history lookup failed: %s", c.name, exc)
            continue
        grab = next((h for h in history if str(h.get("eventType", "")).lower() == "grabbed"), None)
        if not grab:
            continue
        imports = [h for h in history if "imported" in str(h.get("eventType", "")).lower()]
        removal = Removal(c.name, (grab.get("data") or {}).get("indexer") or "", imported=bool(imports))
        for rec in imports:
            try:
                removal.library_removed.append(await c.delete_imported(rec))
            except ReplacedSince as exc:
                removal.library_kept.append(str(exc))
            except Exception as exc:
                path = (rec.get("data") or {}).get("importedPath") or "an imported file"
                log.warning("%s: could not delete %s: %s", c.name, path, exc)
                removal.library_errors.append(path)
        try:
            await c.mark_failed(grab["id"])
        except Exception as exc:
            log.warning("%s: could not mark the grab failed: %s", c.name, exc)
        return removal
    return None


class ProwlarrClient:
    def __init__(self, cfg: ProwlarrConfig, transport: httpx.AsyncBaseTransport | None = None):
        self.http = httpx.AsyncClient(base_url=cfg.url.rstrip("/") + "/api/v1", timeout=30, transport=transport,
                                      headers={"X-Api-Key": cfg.api_key})

    async def close(self) -> None:
        await self.http.aclose()

    async def status(self) -> dict:
        r = await self.http.get("/system/status")
        r.raise_for_status()
        return r.json()

    async def indexers(self) -> list[dict]:
        r = await self.http.get("/indexer")
        r.raise_for_status()
        return [{"id": i.get("id"), "name": i.get("name", ""), "enabled": i.get("enable", False),
                 "protocol": i.get("protocol", "")} for i in r.json()]
