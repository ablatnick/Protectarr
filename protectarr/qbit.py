"""qBittorrent Web API v2 client (works with qBittorrent 4.x and 5.x)."""

from __future__ import annotations

import time

import httpx

NO_METADATA_STATES = {"metaDL", "forcedMetaDL"}
BUSY_STATES = {"checkingUP", "checkingDL", "checkingResumeData", "moving", "allocating"}
STOPPED_STATES = {"stoppedDL", "pausedDL"}
PAUSED_STATES = STOPPED_STATES | {"stoppedUP", "pausedUP"}


# After a failed login, wait this long (doubling up to the maximum) before trying again. qBittorrent bans an
# address after 5 failed logins by default, and the poll loop would otherwise hit that within half a minute.
LOGIN_BACKOFF_SECONDS = 60
LOGIN_BACKOFF_MAX_SECONDS = 900


class QbitError(RuntimeError):
    pass


class QbitClient:
    def __init__(self, url: str, username: str, password: str, transport: httpx.AsyncBaseTransport | None = None):
        self.url = url.strip()
        self.username, self.password = username, password
        self.http = httpx.AsyncClient(base_url=self.url.rstrip("/") + "/api/v2", timeout=30, transport=transport,
                                      headers={"Referer": self.url})
        self._logged_in = False
        self._login_failures = 0
        self._retry_at = 0.0
        self._last_error = ""

    @property
    def configured(self) -> bool:
        return bool(self.url)

    async def close(self) -> None:
        await self.http.aclose()

    async def login(self) -> None:
        if not self.configured:
            raise QbitError("qBittorrent isn't set up yet: enter its address on the Settings page")
        wait = self._retry_at - time.monotonic()
        if wait > 0:
            raise QbitError(f"{self._last_error} Trying again in {int(wait) + 1}s, or save the Settings page to retry now.")
        r = await self.http.post("/auth/login", data={"username": self.username, "password": self.password})
        body = r.text.strip()
        # qBittorrent 5.1+ answers a good login with 204 and no body; older versions with 200 "Ok.".
        if r.status_code in (200, 204) and body != "Fails.":
            self._logged_in, self._login_failures, self._retry_at = True, 0, 0.0
            return
        self._login_failures += 1
        backoff = min(LOGIN_BACKOFF_SECONDS * 2 ** (self._login_failures - 1), LOGIN_BACKOFF_MAX_SECONDS)
        if r.status_code == 403 and "banned" in body.lower():
            self._last_error = ("qBittorrent has banned Protectarr's address after too many failed logins. Restart "
                                "qBittorrent (or wait for the ban to end, 1 hour by default), then check the password.")
            backoff = max(backoff, 300)
        else:
            self._last_error = f"qBittorrent rejected the username or password (HTTP {r.status_code})."
        self._retry_at = time.monotonic() + backoff
        raise QbitError(self._last_error)

    async def _request(self, method: str, path: str, **kw) -> httpx.Response:
        if not self._logged_in:
            await self.login()
        r = await self.http.request(method, path, **kw)
        if r.status_code == 403:  # session expired
            await self.login()
            r = await self.http.request(method, path, **kw)
        return r

    async def _post(self, path: str, data: dict) -> httpx.Response:
        r = await self._request("POST", path, data=data)
        if r.status_code >= 400 and r.status_code != 404:
            raise QbitError(f"POST {path} failed: {r.status_code} {r.text[:200]}")
        return r

    async def version(self) -> str:
        return (await self._request("GET", "/app/version")).text

    async def preferences(self) -> dict:
        r = await self._request("GET", "/app/preferences")
        r.raise_for_status()
        return r.json()

    async def torrents(self) -> list[dict]:
        r = await self._request("GET", "/torrents/info")
        r.raise_for_status()
        return r.json()

    async def torrent(self, torrent_hash: str) -> dict | None:
        r = await self._request("GET", "/torrents/info", params={"hashes": torrent_hash})
        r.raise_for_status()
        items = r.json()
        return items[0] if items else None

    async def files(self, torrent_hash: str) -> list[dict]:
        r = await self._request("GET", "/torrents/files", params={"hash": torrent_hash})
        r.raise_for_status()
        files = r.json()
        for i, f in enumerate(files):
            f.setdefault("index", i)
        return files

    async def piece_states(self, torrent_hash: str) -> list[int]:
        """One entry per piece: 0 not downloaded, 1 downloading, 2 downloaded."""
        r = await self._request("GET", "/torrents/pieceStates", params={"hash": torrent_hash})
        r.raise_for_status()
        return r.json()

    async def first_last_piece_first(self, torrent_hash: str) -> None:
        """Download each file's first and last pieces early (qBittorrent toggles this setting)."""
        await self._post("/torrents/toggleFirstLastPiecePrio", {"hashes": torrent_hash})

    async def skip_files(self, torrent_hash: str, indexes: list[int]) -> None:
        await self._post("/torrents/filePrio", {"hash": torrent_hash, "id": "|".join(map(str, indexes)), "priority": 0})

    async def stop(self, torrent_hash: str) -> None:
        # qBittorrent 5 renamed pause/resume to stop/start.
        if (await self._post("/torrents/stop", {"hashes": torrent_hash})).status_code == 404:
            await self._post("/torrents/pause", {"hashes": torrent_hash})

    async def start(self, torrent_hash: str) -> None:
        if (await self._post("/torrents/start", {"hashes": torrent_hash})).status_code == 404:
            await self._post("/torrents/resume", {"hashes": torrent_hash})

    async def delete(self, torrent_hash: str, delete_files: bool) -> None:
        await self._post("/torrents/delete", {"hashes": torrent_hash, "deleteFiles": str(delete_files).lower()})

    async def remove_tags(self, torrent_hash: str, tags: str) -> None:
        await self._post("/torrents/removeTags", {"hashes": torrent_hash, "tags": tags})

    async def add_tags(self, torrent_hash: str, tags: str) -> None:
        await self._post("/torrents/addTags", {"hashes": torrent_hash, "tags": tags})


def has_metadata(t: dict) -> bool:
    # A magnet that's queued or stopped before its metadata arrived isn't in metaDL, so also trust qBittorrent's
    # own flag (5.x sends it) when it's there.
    return t.get("state") not in NO_METADATA_STATES and t.get("has_metadata", True) is not False


def is_complete(t: dict) -> bool:
    return t.get("progress", 0) >= 1 and t.get("state") not in BUSY_STATES
