"""Connection checks for the Connections page and /api/status: is each service reachable, and is it set up
the way Protectarr needs? Nothing here ever returns a password or API key."""

from __future__ import annotations

import asyncio
import os

import httpx

from .arr import ProwlarrClient
from .guard import Guard, _http_error, _odd_answer
from .qbit import QbitError


def _item(name: str, ok: bool | None, detail: str, hints: list[str] | None = None, url: str = "",
          state: str = "", **extra) -> dict:
    """state: ok | off | setup (not configured yet) | problem."""
    state = state or ("ok" if ok else "off" if ok is None else "problem")
    return {"name": name, "ok": ok, "state": state, "detail": detail, "hints": hints or [], "url": url, **extra}


async def check_qbit(guard: Guard) -> dict:
    cfg = guard.cfg.qbittorrent
    if not guard.qbit.configured:
        return _item("qBittorrent", False, "not set up yet", ["Enter qBittorrent's address, username and password "
                                                              "below (qBittorrent: Options > Web UI)."], state="setup")
    try:
        version = (await guard.qbit.version()).strip()
        prefs = await guard.qbit.preferences()
    except QbitError as exc:
        hint = [] if "banned" in str(exc) else ["Check the username and password (qBittorrent: Options > Web UI)."]
        return _item("qBittorrent", False, str(exc), hint, cfg.url)
    except httpx.HTTPError as exc:
        return _item("qBittorrent", False, _http_error(exc),
                     ["Check the address and port. Use an address Protectarr can reach: the server's IP, or the "
                      "container name (http://qbittorrent:8080) if both are on the same Docker network."],
                     cfg.url)
    hints = []
    stop_ok = prefs.get("torrent_stop_condition") == "MetadataReceived"
    if not stop_ok:
        hints.append("Set Options > Downloads > Torrent stop condition to 'Metadata received' so new torrents "
                     "wait for Protectarr's check before anything downloads.")
    if not prefs.get("temp_path_enabled"):
        hints.append("Turn on Options > Downloads > 'Keep incomplete torrents in' so half-finished files "
                     "stay in a separate folder.")
    added = prefs.get("autorun_on_torrent_added_enabled") and "protectarr" in prefs.get("autorun_on_torrent_added_program", "")
    finished = prefs.get("autorun_enabled") and "protectarr" in prefs.get("autorun_program", "")
    if not (added and finished):
        hints.append("Optional: add the 'Run external program' hooks from the README so Protectarr reacts "
                     "instantly instead of within a few seconds.")
    unseen = []
    for key, on in (("save_path", True), ("temp_path", prefs.get("temp_path_enabled"))):
        remote = (prefs.get(key) or "").rstrip("/")
        if on and remote and not os.path.isdir(guard.cfg.to_local(remote)):
            unseen.append(f"{remote} (looked for {guard.cfg.to_local(remote)})")
    if unseen:
        hints.insert(0, "Protectarr can't see qBittorrent's download folder " + ", ".join(unseen) + ". Mount it into "
                     "Protectarr at the same path, or add a PATH_MAPPINGS entry; until then every finished download "
                     "is held because its files can't be checked.")
    return _item("qBittorrent", True, f"connected, {version}", hints, cfg.url, stop_condition_ok=stop_ok,
                 folders_ok=not unseen)


async def check_arr(guard: Guard, client) -> dict:
    try:
        st = await client.status()
    except httpx.HTTPError as exc:
        return _item(client.name, False, _http_error(exc),
                     [f"Check the address and the API key ({client.cfg.kind.capitalize()}: Settings > General > "
                      "Security > API Key)."], client.cfg.url)
    cats = sorted(k for k, v in guard.discovered.items() if v.get("source") == client.name)
    hints = []
    if not cats and not guard.cfg.qbittorrent.categories:
        hints.append("No qBittorrent download client with a category was found. In Settings > Download Clients, "
                     "give the qBittorrent client a category so Protectarr knows which torrents belong to this app.")
    detail = f"connected, v{st.get('version', '?')}; categories: {', '.join(cats) or 'none'}"
    return _item(client.name, True, detail, hints, client.cfg.url)


async def check_clamav(guard: Guard) -> dict:
    cfg = guard.cfg.clamav
    clamd = guard.scanner.clamd
    if not cfg.enabled:
        return _item("ClamAV", None, "turned off", ["Turn it on to scan non-video files for known malware."])
    if clamd is None:
        return _item("ClamAV", None, "not set up yet",
                     ["Recommended: run ClamAV (docker run -d -p 3310:3310 clamav/clamav:stable) and enter its "
                      "host and port below."], state="setup")
    if not await clamd.ping():
        return _item("ClamAV", False, f"no answer from {cfg.host}:{cfg.port}",
                     ["ClamAV needs a few minutes to download its signatures after its first start.",
                      "Check the host and port (3310), and that clamd's TCP port is reachable from Protectarr."])
    try:
        version = await clamd.version()
    except (OSError, asyncio.TimeoutError):
        version = "version unknown"
    return _item("ClamAV", True, f"online, {version}")


async def check_prowlarr(guard: Guard) -> dict | None:
    cfg = guard.cfg.prowlarr
    if not cfg.url:
        return None
    client = ProwlarrClient(cfg)
    try:
        st = await client.status()
        idx = await client.indexers()
    except httpx.HTTPError as exc:
        return _item("Prowlarr", False, _http_error(exc),
                     ["Check the address and the API key (Prowlarr: Settings > General > Security)."], cfg.url)
    finally:
        await client.close()
    on = sum(1 for i in idx if i["enabled"])
    return _item("Prowlarr", True, f"connected, v{st.get('version', '?')}; {on} of {len(idx)} indexers enabled",
                 url=cfg.url)


def check_paths(guard: Guard) -> dict:
    problems = []
    for label, path in (("quarantine", guard.cfg.quarantine_dir), ("data", guard.cfg.data_dir)):
        if not os.access(path, os.W_OK):
            problems.append(f"{label} folder {path} is not writable by uid {os.getuid()}")
    if problems:
        return _item("Folders", False, "; ".join(problems),
                     ["Run Protectarr as the same user as qBittorrent (user: PUID:PGID) and make the folders "
                      "writable by it."])
    return _item("Folders", True, f"quarantine and data folders are writable (running as uid {os.getuid()})")


CHECK_TIMEOUT_SECONDS = 8


async def _limited(check, name: str, url: str) -> dict | None:
    """A wrong IP can leave a connection hanging for minutes; the page shouldn't wait for it."""
    try:
        return await asyncio.wait_for(check, CHECK_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        return _item(name, False, f"no answer within {CHECK_TIMEOUT_SECONDS}s",
                     ["Check the address and port, and that nothing (a firewall, a VPN container) blocks it."], url)
    except Exception as exc:  # e.g. the address serves some other web page
        return _item(name, False, _odd_answer(exc), ["Check the address and port."], url)


async def run_checks(guard: Guard) -> dict:
    if guard.arrs:
        try:
            await asyncio.wait_for(guard.refresh_categories(), CHECK_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            pass
    names = ["qBittorrent", "ClamAV", "Prowlarr", *(c.name for c in guard.arrs)]
    urls = [guard.cfg.qbittorrent.url, "", guard.cfg.prowlarr.url, *(c.cfg.url for c in guard.arrs)]
    checks = [check_qbit(guard), check_clamav(guard), check_prowlarr(guard), *(check_arr(guard, c) for c in guard.arrs)]
    results = await asyncio.gather(*(_limited(c, n, u) for c, n, u in zip(checks, names, urls)))
    services = [r for r in results if r is not None]
    services.append(check_paths(guard))
    categories = guard.category_table()
    by = {x["name"]: x for x in services}
    checklist = [
        {"done": by["qBittorrent"]["ok"] is True, "text": "Connect qBittorrent"},
        {"done": any(by.get(c.name, {}).get("ok") for c in guard.arrs) or bool(guard.cfg.qbittorrent.categories),
         "text": "Add at least one of Sonarr, Radarr, Lidarr or Readarr"},
        {"done": by["ClamAV"]["ok"] is True or not guard.cfg.clamav.enabled,
         "text": "Connect ClamAV (recommended)"},
        {"done": bool(by["qBittorrent"].get("stop_condition_ok")),
         "text": "In qBittorrent, set Options > Downloads > Torrent stop condition to \"Metadata received\""},
        {"done": bool(guard.cfg.api_key),
         "text": "Protect this page: set PROTECTARR_API_KEY on the container (skip if only you can reach it)"},
    ]
    warnings = []
    if guard.arrs and not any(c["watched"] for c in categories):
        warnings.append("No qBittorrent categories are being watched yet, so nothing is checked. Fix the *arr "
                        "connections below, or fill in their categories.")
    if by["qBittorrent"].get("folders_ok") is False:
        warnings.append(by["qBittorrent"]["hints"][0])
    folders = by["Folders"]
    if not folders["ok"]:
        warnings.append(folders["detail"] + ". " + " ".join(folders["hints"]))
    return {"ok": all(s["ok"] is not False for s in services), "config_source": guard.cfg.source,
            "services": services, "categories": categories, "warnings": warnings, "checklist": checklist,
            "setup_done": all(c["done"] for c in checklist[:2])}
