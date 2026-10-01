"""Connecting to the *arr stack: env-only config, category discovery, music/book profiles, indexers, status."""

import json
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

from protectarr.arr import ArrClient
from protectarr.config import ArrConfig, from_env
from protectarr.db import Store
from protectarr.filetype import sniff_bytes
from protectarr.findings import Level
from protectarr.guard import Guard
from protectarr.qbit import QbitClient
from protectarr.quarantine import Quarantine
from protectarr.rules import TorrentFile, check_metadata
from protectarr.scanner import Scanner
from protectarr.web import create_app
from conftest import DEFAULT_LOGIN, MKV, PE
from test_guard import FakeQbit

MB = 1024 * 1024


# ----- configuration from environment variables -----------------------------------------------------------

def test_env_config_finds_every_arr_app():
    cfg = from_env({
        "QBIT_URL": "http://qb:8080", "QBIT_PASSWORD": "pw",
        "SONARR_URL": "http://sonarr:8989", "SONARR_API_KEY": "s",
        "SONARR_4K_URL": "http://sonarr4k:8989", "SONARR_4K_API_KEY": "s4",
        "RADARR_URL": "http://radarr:7878", "RADARR_API_KEY": "r", "RADARR_CATEGORIES": "movies, movies-uhd",
        "LIDARR_URL": "http://lidarr:8686", "LIDARR_API_KEY": "l",
        "READARR_URL": "", "PROWLARR_URL": "http://prowlarr:9696", "PROWLARR_API_KEY": "p",
        "CLAMAV_HOST": "av", "CLAMAV_STREAM_MAX_MB": "100", "PATH_MAPPINGS": "/downloads:/data/downloads",
        "CATEGORY_PROFILES": "audiobooks=book", "ACTION_SUSPICIOUS": "block", "PROTECTARR_API_KEY": "k",
    })
    arrs = {a.name: a for a in cfg.arr}
    assert set(arrs) == {"Sonarr", "Sonarr 4K", "Radarr", "Lidarr"}  # empty READARR_URL is skipped
    assert arrs["Lidarr"].api_version == "v1" and arrs["Lidarr"].profile == "music"
    assert arrs["Radarr"].categories == ["movies", "movies-uhd"]
    assert cfg.qbittorrent.password == "pw" and cfg.prowlarr.url == "http://prowlarr:9696"
    assert cfg.clamav.host == "av" and cfg.clamav.stream_max_mb == 100
    assert cfg.to_local("/downloads/x.mkv") == "/data/downloads/x.mkv"
    assert cfg.rules.category_profiles == {"audiobooks": "book"} and cfg.actions["suspicious"] == "block"
    assert cfg.source == "environment variables"


def test_env_config_rejects_bad_values():
    with pytest.raises(ValueError):
        from_env({"ACTION_MALICIOUS": "ignore"})
    with pytest.raises(ValueError):
        from_env({"CATEGORY_PROFILES": "x=podcast"})


# ----- music and book rules ----------------------------------------------------------------------------------

def files(*pairs):
    return [TorrentFile(n, s) for n, s in pairs]


def test_music_release_with_cue_log_and_booklet_is_clean():
    v = check_metadata(files(("Album/01.flac", 30 * MB), ("Album/album.cue", 1000), ("Album/rip.log", 5000),
                             ("Album/booklet.pdf", 2 * MB), ("Album/cover.jpg", 300000)), 30 * MB, profile="music")
    assert v.level == Level.CLEAN, v.summary()


def test_music_release_bait():
    v = check_metadata(files(("Album/01 - Song.mp3.exe", 5 * MB)), 0, profile="music")
    assert v.level == Level.MALICIOUS and "pretends to be an audio file" in v.summary()
    v = check_metadata(files(("Album/password.txt", 100), ("Album/Album.zip", 80 * MB)), 0, profile="music")
    assert v.level == Level.SUSPICIOUS and {f.code for f in v.findings} >= {"lure_name", "archive", "no_media"}


def test_book_releases():
    assert check_metadata(files(("Book.epub", 2 * MB)), 0, profile="book").level == Level.CLEAN
    assert check_metadata(files(("Book/Book.pdf", 9 * MB)), 0, profile="book").level == Level.CLEAN
    assert check_metadata(files(("Audiobook/01.m4b", 300 * MB), ("Audiobook/cover.jpg", 1000)), 0,
                          profile="book").level == Level.CLEAN
    assert check_metadata(files(("Book.pdf.exe", 2 * MB)), 0, profile="book").level == Level.MALICIOUS
    # The same PDF in a TV release is a lure.
    assert check_metadata(files(("Show.mkv", 400 * MB), ("Watch here.pdf", 100)), 30 * MB).level == Level.SUSPICIOUS


def test_audio_and_ebook_signatures():
    assert sniff_bytes(b"fLaC\0\0\0\x22") == "flac"
    assert sniff_bytes(b"ID3\x04\0\0") == "mp3"
    assert sniff_bytes(b"OggS\0\x02") == "ogg"
    assert sniff_bytes(b"RIFF\0\0\0\0WAVEfmt ") == "wav"
    assert sniff_bytes(b"\0" * 60 + b"BOOKMOBI" + b"\0" * 20) == "mobi"


def _zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for n, d in entries.items():
            zf.writestr(n, d)
    return str(path)


async def test_epub_is_not_an_archive_but_its_contents_are_checked(tmp_path):
    s = Scanner(None, 25 * MB)
    good = _zip(tmp_path / "a.epub", {"mimetype": "application/epub+zip", "OEBPS/nav.js": "x", "ch1.xhtml": "<p/>"})
    assert (await s.scan([("a.epub", good)], profile="book")).level == Level.CLEAN
    bad = _zip(tmp_path / "b.epub", {"mimetype": "application/epub+zip", "reader.exe": "MZ"})
    assert (await s.scan([("b.epub", bad)], profile="book")).level == Level.MALICIOUS
    # A zip in a TV release is still flagged as an archive.
    z = _zip(tmp_path / "c.zip", {"a.txt": "x"})
    assert {f.code for f in (await s.scan([("c.zip", z)])).findings} == {"archive"}


async def test_known_program_is_not_sent_to_clamav(tmp_path):
    class CountingClamd:
        calls = 0

        async def scan_file(self, path):
            self.calls += 1
            raise AssertionError("should not be called")

    clamd = CountingClamd()
    p = tmp_path / "x.mkv"
    p.write_bytes(PE)
    v = await Scanner(clamd, 25 * MB).scan([("x.mkv", str(p))])
    assert v.level == Level.MALICIOUS and clamd.calls == 0


# ----- the *arr apps ---------------------------------------------------------------------------------------

class FakeArr:
    """Enough of the Sonarr/Radarr/Lidarr API: status, download clients, queue."""

    def __init__(self, version="4.0.0", category_field="tvCategory", category="tv-sonarr", api="v3"):
        self.version, self.api = version, api
        self.clients = [
            {"implementation": "QBittorrent", "enable": True,
             "fields": [{"name": "host", "value": "qbittorrent"}, {"name": category_field, "value": category},
                        {"name": category_field.replace("Category", "ImportedCategory"), "value": "done"}]},
            {"implementation": "Transmission", "enable": True, "fields": [{"name": category_field, "value": "tr"}]},
        ]
        self.queue, self.deleted, self.paths = [], [], []
        self.fail = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        if self.fail:
            return httpx.Response(self.fail)
        path = request.url.path.removeprefix(f"/api/{self.api}")
        if path == "/system/status":
            return httpx.Response(200, json={"version": self.version})
        if path == "/downloadclient":
            return httpx.Response(200, json=self.clients)
        if path == "/queue":
            return httpx.Response(200, json={"page": 1, "pageSize": 200, "totalRecords": len(self.queue),
                                             "records": self.queue})
        if request.method == "DELETE":
            self.deleted.append(int(path.rsplit("/", 1)[1]))
            return httpx.Response(200)
        return httpx.Response(404)


def arr(kind, fake, name=None):
    cfg = ArrConfig(name=name or kind.capitalize(), kind=kind, url=f"http://{kind}", api_key="SECRET-ARR-KEY")
    return ArrClient(cfg, transport=httpx.MockTransport(fake.handler))


@pytest.fixture
def stack(tmp_path):
    cfg = from_env({"DATA_DIR": str(tmp_path / "cfg"), "QUARANTINE_DIR": str(tmp_path / "q"),
                    "PATH_MAPPINGS": f"/downloads:{tmp_path / 'dl'}", "CLAMAV_ENABLED": "false"})
    sonarr = FakeArr()
    lidarr = FakeArr(category_field="musicCategory", category="music", api="v1")
    qb = FakeQbit()
    store = Store(str(tmp_path / "cfg" / "db.sqlite"))
    arrs = [arr("sonarr", sonarr), arr("lidarr", lidarr)]
    cfg.arr = [a.cfg for a in arrs]
    guard = Guard(cfg, store, QbitClient("http://qb", "u", "p", transport=httpx.MockTransport(qb.handler)),
                  arrs, Scanner(None, 25 * MB),
                  Quarantine(cfg.quarantine_dir), background_scans=True)
    return guard, qb, sonarr, lidarr, tmp_path


async def test_categories_are_read_from_the_arr_apps(stack):
    guard, qb, sonarr, lidarr, _ = stack
    await guard.refresh_categories()
    assert guard.discovered == {"tv-sonarr": {"profile": "tv", "source": "Sonarr"},
                                "music": {"profile": "music", "source": "Lidarr"}}
    assert any(p.startswith("/api/v1/") for p in lidarr.paths)  # Lidarr speaks API v1
    assert guard.watched("music") and not guard.watched("done") and not guard.watched("tr")

    # A music release is checked with music rules, so it passes; other categories are left alone.
    qb.add("m1", "Album", [("Album/01.flac", 20 * MB), ("Album/album.cue", 900)], category="music")
    qb.add("x1", "Linux", [("setup.exe", 1 * MB)], category="software")
    await guard.poll()
    assert guard.store.torrent("m1")["metadata_level"] == "clean"
    assert guard.store.torrent("x1") is None


async def test_discovered_categories_survive_an_arr_outage(stack):
    guard, _, sonarr, _, tmp = stack
    await guard.refresh_categories()
    sonarr.fail = 503
    guard2 = Guard(guard.cfg, Store(str(tmp / "cfg" / "db.sqlite")), guard.qbit, guard.arrs, guard.scanner,
                   guard.quarantine)
    await guard2.refresh_categories()
    assert guard2.watched("tv-sonarr") and guard2.arr_errors["Sonarr"] == "HTTP 503"


async def test_indexer_recorded_when_blocking(stack):
    guard, qb, sonarr, _, _ = stack
    await guard.refresh_categories()
    sonarr.queue = [{"id": 3, "downloadId": "BAD1", "indexer": "LimeTorrents (Prowlarr)"}]
    qb.add("bad1", "Show.S01E01", [("Show.S01E01.mkv.exe", 900 * MB)])
    await guard.poll()
    assert sonarr.deleted == [3]
    assert guard.store.events()[0]["indexer"] == "LimeTorrents (Prowlarr)"
    assert guard.store.indexer_stats()[0]["indexer"] == "LimeTorrents (Prowlarr)"


async def test_content_scan_runs_in_the_background(stack):
    guard, qb, _, _, tmp = stack
    await guard.refresh_categories()
    f = tmp / "dl" / "Show.S01E02.mkv"
    f.parent.mkdir(parents=True)
    f.write_bytes(PE)
    qb.add("bg1", "Show.S01E02", [("Show.S01E02.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    await guard.poll()
    await guard.drain()
    assert not f.exists() and guard.store.quarantine_items()


# ----- qBittorrent 5.1 and the web UI -----------------------------------------------------------------------

async def test_qbittorrent_51_login_returns_204():
    def handler(request):
        if request.url.path.endswith("/auth/login"):
            return httpx.Response(204)
        return httpx.Response(200, text="v5.1.2")
    q = QbitClient("http://qb", "u", "p", transport=httpx.MockTransport(handler))
    assert await q.version() == "v5.1.2"


def test_cross_site_posts_refused(stack):
    guard, *_ = stack
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    r = client.post("/review/1/allow", headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/review/1/allow", headers={"origin": "http://testserver"})
    assert r.status_code == 404  # same origin gets through (no such decision)


def test_connections_page_and_status_api(stack):
    guard, qb, sonarr, lidarr, _ = stack
    sonarr.fail = 401
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    status = client.get("/api/status").json()
    by_name = {s["name"]: s for s in status["services"]}
    assert by_name["Sonarr"]["ok"] is False and "API key rejected" in by_name["Sonarr"]["detail"]
    assert by_name["Lidarr"]["ok"] is True and "music" in by_name["Lidarr"]["detail"]
    assert by_name["ClamAV"]["ok"] is None
    assert "SECRET-ARR-KEY" not in json.dumps(status) and "SECRET-ARR-KEY" not in client.get("/connections").text
    html = client.get("/settings").text
    assert "API key rejected" in html and "Torrent stop condition" in html and "SECRET-ARR-KEY" not in html
    assert client.get("/connections", follow_redirects=False).headers["location"] == "/settings"
    assert client.get("/indexers").status_code == 200


# ----- the Settings page -----------------------------------------------------------------------------------

@pytest.fixture
def blank(tmp_path, monkeypatch):
    """A fresh install: no config file, no connection variables, services entered on the Settings page."""
    from protectarr.web import build_guard
    cfg = from_env({"DATA_DIR": str(tmp_path / "cfg"), "QUARANTINE_DIR": str(tmp_path / "q")})
    guard = build_guard(cfg)
    fakes = {"sonarr": FakeArr(), "radarr": FakeArr(category_field="movieCategory", category="radarr")}

    # Route every client Protectarr builds to the fakes, by host name.
    real_init = httpx.AsyncClient.__init__

    def init(self, *args, **kw):
        base = kw.get("base_url", "")
        host = httpx.URL(str(base)).host if base else ""
        if host in fakes:
            kw["transport"] = httpx.MockTransport(fakes[host].handler)
        elif host.startswith("qb"):
            kw["transport"] = httpx.MockTransport(FakeQbit().handler)
        real_init(self, *args, **kw)
    monkeypatch.setattr(httpx.AsyncClient, "__init__", init)
    return guard, fakes


def test_fresh_install_watches_nothing_until_an_arr_app_is_added(blank):
    guard, _ = blank
    assert not guard.watched("tv-sonarr") and not guard.watched("")
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    page = client.get("/settings").text
    assert "Getting started" in page and "Not set up" in page and "Problem" not in page
    assert "isn't checking anything yet" in client.get("/").text


def test_settings_form_adds_services_and_keeps_secrets(blank):
    guard, fakes = blank
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    form = {"qbit_url": "qb:8080", "qbit_username": "admin", "qbit_password": "pw",
            "clamav_host": "clamav", "clamav_port": "3310", "clamav_stream_max_mb": "25",
            "prowlarr_url": "", "prowlarr_api_key": "",
            "arr-new-kind": "sonarr", "arr-new-name": "", "arr-new-url": "sonarr:8989",
            "arr-new-api_key": "SONARR-KEY", "arr-new-categories": ""}
    r = client.post("/settings", data=form, follow_redirects=False)
    assert r.headers["location"] == "/settings?saved=1"
    assert guard.cfg.qbittorrent.url == "http://qb:8080"  # "host:port" is accepted
    assert [(a.name, a.url, a.api_key) for a in guard.cfg.arr] == [("Sonarr", "http://sonarr:8989", "SONARR-KEY")]
    assert guard.cfg.clamav.enabled is False  # unticked box
    assert guard.watched("tv-sonarr")  # categories were read right away

    # Saving again with the secret fields empty keeps them, and a second app can be added.
    form2 = {**form, "qbit_password": "", "arr-0-kind": "sonarr", "arr-0-name": "Sonarr",
             "arr-0-url": "http://sonarr:8989", "arr-0-api_key": "", "arr-0-categories": "",
             "arr-new-kind": "radarr", "arr-new-url": "http://radarr:7878", "arr-new-api_key": "RADARR-KEY",
             "clamav_enabled": "on"}
    client.post("/settings", data=form2)
    assert guard.cfg.qbittorrent.password == "pw"
    assert {a.name: a.api_key for a in guard.cfg.arr} == {"Sonarr": "SONARR-KEY", "Radarr": "RADARR-KEY"}
    assert guard.watched("radarr") and guard.profile("radarr") == "movie" and guard.cfg.clamav.enabled

    # Saved settings survive a restart, and no secret is ever sent back to the browser.
    from protectarr.web import build_guard
    again = build_guard(from_env({"DATA_DIR": guard.cfg.data_dir, "QUARANTINE_DIR": guard.cfg.quarantine_dir}))
    assert {a.name for a in again.cfg.arr} == {"Sonarr", "Radarr"} and again.cfg.qbittorrent.password == "pw"
    page = client.get("/settings").text + json.dumps(client.get("/api/settings").json())
    assert not any(secret in page for secret in ("SONARR-KEY", "RADARR-KEY", '"pw"', "value=\"pw"))

    # Removing an app.
    client.post("/settings", data={**form2, "arr-new-url": "", "arr-1-kind": "radarr", "arr-1-name": "Radarr",
                                   "arr-1-url": "http://radarr:7878", "arr-1-api_key": "", "arr-1-remove": "on"})
    assert [a.name for a in guard.cfg.arr] == ["Sonarr"] and not guard.watched("radarr")


def test_settings_rejects_bad_input(blank):
    guard, _ = blank
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    base = {"qbit_url": "qb:8080", "clamav_port": "3310", "clamav_stream_max_mb": "25"}
    r = client.post("/settings", data={**base, "clamav_port": "abc"}, follow_redirects=False)
    assert "error=" in r.headers["location"]
    r = client.post("/settings", data={**base, "arr-new-kind": "sonarr", "arr-new-url": "sonarr:8989"},
                    follow_redirects=False)
    assert "API%20key" in r.headers["location"] and not guard.cfg.arr


def test_settings_json_api(blank):
    guard, _ = blank
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    r = client.post("/api/settings", json={"arr": [{"kind": "radarr", "url": "http://radarr:7878", "api_key": "K"}]})
    assert r.status_code == 200 and {s["name"] for s in r.json()["services"]} >= {"Radarr"}
    assert client.get("/api/settings").json()["arr"][0]["api_key"] is True
    assert client.post("/api/settings", json={"arr": [{"kind": "plex", "url": "http://x"}]}).status_code == 400


async def test_clean_torrent_started_when_qbittorrent_stops_it_after_the_check(stack):
    guard, qb, _, _, _ = stack
    await guard.refresh_categories()
    qb.add("late", "Show.S01E09", [("Show.S01E09.mkv", 400 * MB)], state="downloading")
    await guard.poll()
    assert not qb.called("/torrents/start")
    qb.torrents["late"]["state"] = "stoppedDL"  # qBittorrent's stop condition kicks in a moment later
    await guard.poll()
    assert qb.called("/torrents/start") == [{"hashes": "late"}]
    await guard.poll()
    assert len(qb.called("/torrents/start")) == 1  # only once


# ----- not getting banned by qBittorrent ---------------------------------------------------------------------

async def test_failed_login_backs_off_instead_of_hammering_qbittorrent():
    from protectarr.qbit import QbitError
    attempts = []

    def handler(request):
        attempts.append(request.url.path)
        return httpx.Response(401, text="Unauthorized")
    q = QbitClient("http://qb", "admin", "wrong", transport=httpx.MockTransport(handler))
    for _ in range(10):  # ten poll cycles
        with pytest.raises(QbitError) as err:
            await q.torrents()
    assert len(attempts) == 1  # one real attempt; the rest wait for the back-off
    assert "Trying again in" in str(err.value)


async def test_ban_is_explained():
    from protectarr.qbit import QbitError
    q = QbitClient("http://qb", "admin", "x", transport=httpx.MockTransport(
        lambda r: httpx.Response(403, text="Your IP address has been banned after too many failed authentication attempts.")))
    with pytest.raises(QbitError, match="Restart qBittorrent"):
        await q.login()


async def test_unconfigured_qbittorrent_is_never_contacted(blank):
    guard, _ = blank
    assert not guard.qbit.configured
    await guard.poll()  # no error, no request
    assert await guard.adopt_existing() == 0
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    q = {s["name"]: s for s in client.get("/api/status").json()["services"]}["qBittorrent"]
    assert q["ok"] is False and q["detail"] == "not set up yet"


async def test_new_torrents_in_other_categories_are_started_but_old_ones_left_alone(stack):
    import time as _t
    guard, qb, _, _, _ = stack
    await guard.refresh_categories()
    qb.add("new1", "Linux.ISO", [("linux.iso", 900 * MB)], category="software", state="downloading")
    qb.torrents["new1"]["added_on"] = _t.time()
    qb.add("old1", "Old.Thing", [("x.iso", 900 * MB)], category="software", state="stoppedDL")
    qb.torrents["old1"]["added_on"] = _t.time() - 3600  # stopped by you an hour ago
    await guard.poll()
    qb.torrents["new1"]["state"] = "stoppedDL"  # the stop condition catches it a moment later
    await guard.poll()
    await guard.poll()
    assert qb.called("/torrents/start") == [{"hashes": "new1"}]
    assert guard.store.torrent("new1") is None and not guard.store.events()  # not checked, just released


# ----- robustness --------------------------------------------------------------------------------------------

def test_reverse_proxy_posts_are_accepted(stack):
    guard, *_ = stack
    guard.cfg.public_url = "https://protectarr.example.com"
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    # Proxy passes the internal Host but the browser's Origin is the public name.
    r = client.post("/review/1/allow", headers={"origin": "https://protectarr.example.com", "host": "protectarr:9797"})
    assert r.status_code == 404
    r = client.post("/review/1/allow", headers={"origin": "https://other.example", "host": "protectarr:9797",
                                                 "x-forwarded-host": "protectarr.lan"})
    assert r.status_code == 403
    r = client.post("/review/1/allow", headers={"origin": "https://protectarr.lan", "host": "protectarr:9797",
                                                 "x-forwarded-host": "protectarr.lan"})
    assert r.status_code == 404


def test_two_apps_with_the_same_name_are_refused(blank):
    guard, _ = blank
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    r = client.post("/api/settings", json={"arr": [{"kind": "radarr", "url": "http://radarr:7878", "api_key": "a"},
                                                   {"kind": "radarr", "url": "http://radarr4k:7878", "api_key": "b"}]})
    assert r.status_code == 400 and "own name" in r.json()["detail"]


async def test_unreadable_download_is_reported_not_retried_forever(stack, monkeypatch):
    guard, qb, _, _, tmp = stack
    await guard.refresh_categories()
    guard.background_scans = False

    async def boom(*a, **k):
        raise PermissionError("[Errno 13] Permission denied: '/downloads/x.mkv'")
    monkeypatch.setattr(guard.scanner, "scan", boom)
    qb.add("perm", "Show.S01E10", [("Show.S01E10.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    for _ in range(5):
        await guard.poll()
    # Not passed as clean: held for a decision, with the reason.
    [d] = guard.store.pending_decisions()
    assert "Permission denied" in d["summary"] and guard.store.torrent("perm")["content_level"] == "held"
    assert qb.called("/torrents/stop")


async def test_unreachable_service_does_not_hang_the_page(stack, monkeypatch):
    import asyncio as _a
    from protectarr import status
    guard, *_ = stack
    monkeypatch.setattr(status, "CHECK_TIMEOUT_SECONDS", 0.2)

    async def hang(*a, **k):
        await _a.sleep(30)
    monkeypatch.setattr(guard.arrs[0], "status", hang)
    monkeypatch.setattr(guard.arrs[0], "qbit_categories", hang)
    res = await _a.wait_for(status.run_checks(guard), 3)
    assert {s["name"]: s for s in res["services"]}["Sonarr"]["detail"].startswith("no answer within")


# ----- second review -----------------------------------------------------------------------------------------

async def test_an_address_that_is_not_an_arr_app_does_not_stop_checking(stack):
    guard, qb, sonarr, _, _ = stack
    sonarr.handler = lambda request: httpx.Response(200, text="<html>router login</html>")
    guard.arrs[0].http._transport = httpx.MockTransport(sonarr.handler)
    await guard.refresh_categories()  # must not raise
    assert "unexpected answer" in guard.arr_errors["Sonarr"]
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    r = client.get("/api/status")
    assert r.status_code == 200
    assert "unexpected answer" in {s["name"]: s for s in r.json()["services"]}["Sonarr"]["detail"]
    assert client.get("/settings").status_code == 200
    # Lidarr's category is still watched and checked.
    qb.add("ok1", "Album", [("Album/01.flac", 20 * MB)], category="music")
    await guard.poll()
    assert guard.store.torrent("ok1")["metadata_level"] == "clean"


def test_real_files_with_unusual_headers_are_recognised():
    from protectarr.filetype import EXPECTED
    assert sniff_bytes(b"ID3\x03\0\0\0\0\0\0fLaC") in EXPECTED[".flac"]
    assert sniff_bytes(b"\0\0\0\x14pnotxxxx") in EXPECTED[".mov"]
    assert sniff_bytes(b"\0\0\x01\xb3\x14\0") in EXPECTED[".mpg"]
    assert sniff_bytes(b"\r\n%PDF-1.7\n") in EXPECTED[".pdf"]
    assert sniff_bytes(b"PK\x03\x04") in EXPECTED[".cbr"] and sniff_bytes(b"Rar!\x1a\x07\0") in EXPECTED[".cbz"]


def test_saved_secrets_are_never_sent_to_a_new_address(blank):
    guard, fakes = blank
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    client.post("/api/settings", json={"qbittorrent": {"url": "http://qb:8080", "username": "admin", "password": "pw"},
                                       "arr": [{"kind": "sonarr", "url": "http://sonarr:8989", "api_key": "SK"}]})
    # Someone points Sonarr at their own server and leaves the key blank: refused.
    r = client.post("/api/settings", json={"arr": [{"id": 0, "kind": "sonarr", "url": "http://evil:8989", "api_key": ""}]})
    assert r.status_code == 400 and "address changed" in r.json()["detail"]
    assert guard.cfg.arr[0].url == "http://sonarr:8989"
    # qBittorrent pointed elsewhere with a blank password gets no password.
    client.post("/api/settings", json={"qbittorrent": {"url": "http://evil:8080", "username": "admin", "password": ""}})
    assert guard.cfg.qbittorrent.password == ""
    # Same address, blank key: kept.
    client.post("/api/settings", json={"arr": [{"id": 0, "kind": "sonarr", "url": "sonarr:8989/", "api_key": ""}]})
    assert guard.cfg.arr[0].api_key == "SK"


def test_review_errors_are_shown_not_a_crash(stack, monkeypatch):
    import asyncio as _a
    guard, qb, *_ = stack
    _a.run(guard.refresh_categories())
    qb.add("h1", "Show.S01E11", [("Show.S01E11.mkv", 2 * MB)])
    _a.run(guard.poll())
    [d] = guard.store.pending_decisions()

    async def broken(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(guard, "allow", broken)
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    r = client.post(f"/review/{d['id']}/allow")
    assert r.status_code == 200 and "Allow failed: disk full" in r.text


# ----- import race: checking while downloading, and cleaning up after an import ------------------------------

async def test_disguised_program_caught_while_still_downloading(stack):
    guard, qb, sonarr, _, tmp = stack
    await guard.refresh_categories()
    incomplete = tmp / "dl" / "incomplete"
    f = incomplete / "Show.S02E01" / "Show.S02E01.mkv"
    f.parent.mkdir(parents=True)
    f.write_bytes(PE + b"\0" * 4096)  # only the first piece has arrived
    qb.add("early1", "Show.S02E01", [("Show.S02E01/Show.S02E01.mkv", 900 * MB)], state="downloading", progress=0.02,
           save="/downloads/complete")
    qb.torrents["early1"]["download_path"] = "/downloads/incomplete"
    qb.files["early1"][0].update(progress=0.02, piece_range=[0, 3599])
    qb.pieces["early1"] = [2] + [0] * 3599
    sonarr.queue = [{"id": 21, "downloadId": "EARLY1", "indexer": "BadTracker"}]
    await guard.poll()  # file list passes; then the first piece shows what it really is
    await guard.drain()
    assert qb.called("/torrents/toggleFirstLastPiecePrio") == [{"hashes": "early1"}]
    [e] = [e for e in guard.store.events() if e["stage"] == "early"]
    assert e["level"] == "malicious" and "really a program" in e["summary"] and e["indexer"] == "BadTracker"
    assert sonarr.deleted == [21] and not f.exists() and guard.store.quarantine_items()


async def test_finished_extra_file_scanned_before_the_torrent_completes(stack):
    guard, qb, _, _, tmp = stack
    await guard.refresh_categories()
    folder = tmp / "dl" / "Show.S02E02"
    folder.mkdir(parents=True)
    _zip(folder / "subs.zip", {"setup.exe": "MZ"})
    (folder / "Show.S02E02.mkv").write_bytes(MKV)
    qb.add("early2", "Show.S02E02", [("Show.S02E02/Show.S02E02.mkv", 900 * MB), ("Show.S02E02/subs.zip", 1 * MB)],
           state="downloading", progress=0.4)
    qb.files["early2"][0].update(progress=0.4, piece_range=[0, 99])
    qb.files["early2"][1].update(progress=1.0, piece_range=[100, 100])
    qb.pieces["early2"] = [2] * 40 + [0] * 60 + [2]
    guard.cfg.rules.allow_archives = True  # so the file list passes; the zip's contents give it away
    await guard.poll()
    await guard.drain()
    [e] = [e for e in guard.store.events() if e["stage"] == "early"]
    assert "contains program files" in e["summary"] and qb.called("/torrents/delete")


async def test_clean_download_is_only_scanned_once(stack, monkeypatch):
    guard, qb, _, _, tmp = stack
    await guard.refresh_categories()
    guard.background_scans = False
    folder = tmp / "dl" / "Show.S02E03"
    folder.mkdir(parents=True)
    (folder / "Show.S02E03.mkv").write_bytes(MKV)
    (folder / "Show.S02E03.srt").write_bytes(b"1\n00:00:01,000 --> 00:00:02,000\nHi\n")
    qb.add("once", "Show.S02E03", [("Show.S02E03/Show.S02E03.mkv", 400 * MB), ("Show.S02E03/Show.S02E03.srt", 100)],
           state="downloading", progress=0.5)
    qb.files["once"][1].update(progress=1.0)
    await guard.poll()  # the subtitle finished first and is scanned now
    scanned = []
    real = guard.scanner.scan

    async def spy(files, profile="tv"):
        scanned.extend(n for n, _ in files)
        return await real(files, profile)
    monkeypatch.setattr(guard.scanner, "scan", spy)
    qb.torrents["once"].update(state="stalledUP", progress=1.0)
    await guard.poll()
    assert scanned == ["Show.S02E03/Show.S02E03.mkv"]
    assert guard.store.torrent("once")["content_level"] == "clean"


class ImportedSonarr(FakeArr):
    """Sonarr after it already imported the download: not in the queue, but in history and the library."""

    def __init__(self):
        super().__init__()
        self.library = [{"id": 501, "path": "/tv/Show/Season 2/Show - S02E04.mkv"}]
        self.failed = []

    def handler(self, request):
        path = request.url.path.removeprefix("/api/v3")
        if path == "/history":
            assert request.url.params["downloadId"] == "IMP1"
            return httpx.Response(200, json={"records": [
                {"id": 9001, "eventType": "downloadFolderImported", "downloadId": "IMP1", "seriesId": 7,
                 "data": {"importedPath": "/tv/Show/Season 2/Show - S02E04.mkv"}},
                {"id": 9000, "eventType": "grabbed", "downloadId": "IMP1", "seriesId": 7,
                 "data": {"indexer": "BadTracker (Prowlarr)"}}]})
        if path == "/episodefile" and request.method == "GET":
            assert request.url.params["seriesId"] == "7"
            return httpx.Response(200, json=self.library)
        if path.startswith("/episodefile/") and request.method == "DELETE":
            self.library = [f for f in self.library if f["id"] != int(path.rsplit("/", 1)[1])]
            return httpx.Response(200)
        if path.startswith("/history/failed/"):
            self.failed.append(int(path.rsplit("/", 1)[1]))
            return httpx.Response(200)
        return super().handler(request)


async def test_bad_download_already_imported_is_removed_from_the_library(stack):
    guard, qb, _, _, tmp = stack
    sonarr = ImportedSonarr()
    guard.arrs[0].http._transport = httpx.MockTransport(sonarr.handler)
    await guard.refresh_categories()
    guard.background_scans = False
    f = tmp / "dl" / "Show.S02E04" / "Show.S02E04.mkv"
    f.parent.mkdir(parents=True)
    f.write_bytes(PE)
    qb.add("imp1", "Show.S02E04", [("Show.S02E04/Show.S02E04.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    await guard.poll()
    assert sonarr.library == [] and sonarr.failed == [9000]  # deleted from the library, grab marked failed
    assert qb.called("/torrents/delete")  # Sonarr no longer manages it, so Protectarr removes the torrent
    e = guard.store.events()[0]
    assert "had already imported it" in e["action"] and "deleted 1 imported file" in e["action"]
    assert e["indexer"] == "BadTracker (Prowlarr)"
