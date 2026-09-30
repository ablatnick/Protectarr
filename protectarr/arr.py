"""Sonarr/Radarr/Lidarr/Readarr/Whisparr: find which qBittorrent categories they use, and remove and
blocklist rejected downloads. Prowlarr: list indexers so bad releases can be traced to their source."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from .config import ArrConfig, ProwlarrConfig

log = logging.getLogger(__name__)
# Every *arr app ignores the query parameters it doesn't know, so one set covers them all.
UNKNOWN_ITEMS = {"includeUnknownSeriesItems": "true", "includeUnknownMovieItems": "true",
                 "includeUnknownArtistItems": "true", "includeUnknownAuthorItems": "true"}


@dataclass
class Removal:
    app: str
    indexer: str = ""


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


async def blocklist_everywhere(clients: list[ArrClient], torrent_hash: str) -> Removal | None:
    """Remove the download from whichever *arr app owns it, which blocklists the release there."""
    owner = await find_owner(clients, torrent_hash)
    if not owner:
        return None
    client, item = owner
    try:
        await client.remove_and_blocklist(item["id"])
    except Exception as exc:
        log.warning("%s: queue removal failed: %s", client.name, exc)
        return None
    return Removal(client.name, item.get("indexer") or "")


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
