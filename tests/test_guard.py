"""End-to-end pipeline tests against fake qBittorrent and Sonarr APIs."""

import json
from urllib.parse import parse_qs

import httpx
import pytest

from protectarr.arr import ArrClient
from protectarr.config import from_dict
from protectarr.db import Store
from protectarr.guard import Guard
from protectarr.notify import Notifier
from protectarr.qbit import QbitClient
from protectarr.quarantine import Quarantine
from protectarr.scanner import Scanner
from conftest import MKV, PE

MB = 1024 * 1024


class FakeQbit:
    def __init__(self):
        self.torrents = {}
        self.files = {}
        self.calls = []

    def add(self, h, name, files, state="downloading", progress=0.0, save="/downloads", category="tv-sonarr"):
        self.torrents[h] = {"hash": h, "name": name, "state": state, "progress": progress,
                            "save_path": save, "category": category}
        self.files[h] = [{"name": n, "size": s, "priority": 1} for n, s in files]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v2")
        form = parse_qs(request.content.decode()) if request.method == "POST" else {}
        self.calls.append((path, {k: v[0] for k, v in form.items()}))
        if path == "/auth/login":
            return httpx.Response(200, text="Ok.")
        if path == "/app/version":
            return httpx.Response(200, text="v5.1.2")
        if path == "/app/preferences":
            return httpx.Response(200, json={"torrent_stop_condition": "None", "temp_path_enabled": True})
        if path == "/torrents/info":
            h = request.url.params.get("hashes")
            items = [t for k, t in self.torrents.items() if h in (None, k)]
            return httpx.Response(200, json=items)
        if path == "/torrents/files":
            return httpx.Response(200, json=self.files[request.url.params["hash"]])
        if path == "/torrents/delete":
            self.torrents.pop(form["hashes"][0], None)
        return httpx.Response(200, text="")

    def called(self, path):
        return [c for p, c in self.calls if p == path]


class FakeSonarr:
    def __init__(self):
        self.queue = []
        self.deleted = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"page": 1, "pageSize": 200, "totalRecords": len(self.queue),
                                             "records": self.queue})
        qid = int(request.url.path.rsplit("/", 1)[1])
        self.deleted.append((qid, dict(request.url.params)))
        return httpx.Response(200)


@pytest.fixture
def env(tmp_path):
    cfg = from_dict({
        "qbittorrent": {"categories": ["tv-sonarr"]},
        "arr": [{"name": "Sonarr", "kind": "sonarr", "url": "http://sonarr", "api_key": "k"}],
        "path_mappings": [{"remote": "/downloads", "local": str(tmp_path / "dl")}],
        "quarantine_dir": str(tmp_path / "q"), "data_dir": str(tmp_path / "cfg"),
    })
    qb, sonarr = FakeQbit(), FakeSonarr()
    guard = Guard(cfg, Store(str(tmp_path / "cfg" / "db.sqlite")),
                  QbitClient("http://qb", "u", "p", transport=httpx.MockTransport(qb.handler)),
                  [ArrClient(cfg.arr[0], transport=httpx.MockTransport(sonarr.handler))],
                  Scanner(None, 25 * MB), Quarantine(cfg.quarantine_dir), Notifier([]))
    return guard, qb, sonarr, tmp_path


async def test_bait_blocked_before_download(env):
    guard, qb, sonarr, _ = env
    qb.add("aaa", "Show.S01E01", [("Show.S01E01/Show.S01E01.mkv.exe", 600 * MB)])
    sonarr.queue = [{"id": 7, "downloadId": "AAA"}]
    await guard.poll()
    assert sonarr.deleted == [(7, {"removeFromClient": "true", "blocklist": "true"})]
    assert guard.store.is_blocked("aaa")
    events = guard.store.events()
    assert events[0]["level"] == "malicious" and "Sonarr" in events[0]["action"]


async def test_unknown_to_sonarr_is_deleted_in_qbittorrent(env):
    guard, qb, sonarr, _ = env
    qb.add("bbb", "Show.S01E02", [("Show/setup.exe", 1 * MB), ("Show/Show.mkv", 500 * MB)])
    await guard.poll()
    assert qb.called("/torrents/delete") == [{"hashes": "bbb", "deleteFiles": "true"}]


async def test_clean_torrent_resumed_then_disguised_program_quarantined(env):
    guard, qb, sonarr, tmp = env
    qb.add("ccc", "Show.S01E03", [("Show.S01E03/Show.S01E03.mkv", 400 * MB)], state="stoppedDL")
    await guard.poll()
    assert qb.called("/torrents/start") == [{"hashes": "ccc"}]
    assert not sonarr.deleted

    # Download finishes, but the "video" is really a Windows program.
    f = tmp / "dl" / "Show.S01E03" / "Show.S01E03.mkv"
    f.parent.mkdir(parents=True)
    f.write_bytes(PE)
    qb.torrents["ccc"].update(state="stalledUP", progress=1.0)
    sonarr.queue = [{"id": 9, "downloadId": "CCC"}]
    await guard.poll()

    assert not f.exists()
    held = guard.store.quarantine_items()
    assert len(held) == 1 and held[0]["level"] == "malicious"
    rec = guard.quarantine.record(held[0]["id"])
    assert rec["files"][0]["original_path"] == str(f)
    assert sonarr.deleted[0][0] == 9

    # Restoring puts the file back.
    guard.quarantine.restore(held[0]["id"])
    assert f.read_bytes() == PE


async def test_real_video_passes_both_stages(env):
    guard, qb, sonarr, tmp = env
    f = tmp / "dl" / "Show.S01E04.mkv"
    f.parent.mkdir(parents=True)
    f.write_bytes(MKV)
    qb.add("ddd", "Show.S01E04", [("Show.S01E04.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    await guard.poll()
    row = guard.store.torrent("ddd")
    assert (row["metadata_level"], row["content_level"]) == ("clean", "clean")
    assert f.exists() and not sonarr.deleted


async def test_other_categories_ignored(env):
    guard, qb, _, _ = env
    qb.add("eee", "Some.Linux.ISO", [("setup.exe", 1 * MB)], category="software")
    await guard.poll()
    assert guard.store.torrent("eee") is None


async def test_first_run_leaves_finished_torrents_alone(env):
    guard, qb, _, _ = env
    qb.add("fff", "Old.Show", [("Old.Show/setup.exe", 1 * MB)], state="stalledUP", progress=1.0)
    assert await guard.adopt_existing() == 1
    await guard.poll()
    assert not qb.called("/torrents/delete")


async def test_readded_blocked_torrent_is_removed_again(env):
    guard, qb, _, _ = env
    guard.store.block_hash("ggg", "Bad", "earlier")
    qb.add("ggg", "Bad", [("Bad.mkv", 900 * MB)])
    await guard.poll()
    assert qb.called("/torrents/delete")


async def test_alert_mode_tags_instead_of_blocking(env):
    guard, qb, sonarr, _ = env
    guard.cfg.actions["suspicious"] = "alert"
    qb.add("hhh", "Show.S01E05", [("Show.S01E05.wmv", 400 * MB)])
    await guard.poll()
    assert qb.called("/torrents/addTags") == [{"hashes": "hhh", "tags": "protectarr-suspicious"}]
    assert not qb.called("/torrents/delete") and not sonarr.deleted


async def test_suspicious_held_then_allowed(env):
    guard, qb, sonarr, tmp = env
    qb.add("iii", "Show.S01E06", [("Show.S01E06/Show.S01E06.wmv", 400 * MB)], state="stoppedDL")
    await guard.poll()
    assert not qb.called("/torrents/start")  # stays stopped while waiting
    assert qb.called("/torrents/addTags") == [{"hashes": "iii", "tags": "protectarr-held"}]
    [d] = guard.store.pending_decisions()
    assert d["stage"] == "metadata" and d["level"] == "suspicious"

    await guard.poll()  # still waiting: nothing new happens
    assert len(guard.store.pending_decisions()) == 1 and not sonarr.deleted

    await guard.allow(d["id"])
    assert qb.called("/torrents/start") == [{"hashes": "iii"}]
    assert not guard.store.pending_decisions()

    # It then downloads and still gets the after-download scan.
    f = tmp / "dl" / "Show.S01E06" / "Show.S01E06.wmv"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11" + b"\0" * 100)
    qb.torrents["iii"].update(state="stalledUP", progress=1.0)
    await guard.poll()
    assert guard.store.torrent("iii")["content_level"] == "clean"


async def test_suspicious_held_then_denied(env):
    guard, qb, sonarr, _ = env
    qb.add("jjj", "Show.S01E07", [("Show.S01E07.mkv", 2 * MB)])  # far too small
    sonarr.queue = [{"id": 11, "downloadId": "JJJ"}]
    await guard.poll()
    [d] = guard.store.pending_decisions()
    await guard.deny(d["id"])
    assert sonarr.deleted == [(11, {"removeFromClient": "true", "blocklist": "true"})]
    assert guard.store.is_blocked("jjj")
    with pytest.raises(LookupError):
        await guard.deny(d["id"])


async def test_held_after_download_files_locked_away_until_allowed(env):
    guard, qb, sonarr, tmp = env
    f = tmp / "dl" / "Show.S01E08.mkv"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"not really a video")
    qb.add("kkk", "Show.S01E08", [("Show.S01E08.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    await guard.poll()
    assert not f.exists()  # Sonarr can't import it while it waits
    [d] = guard.store.pending_decisions()
    assert d["stage"] == "content" and d["quarantine_id"]

    await guard.allow(d["id"])
    assert f.read_bytes() == b"not really a video"
    assert guard.store.quarantine_item(d["quarantine_id"])["status"] == "restored"
    await guard.poll()
    assert not guard.store.pending_decisions() and not sonarr.deleted


async def test_malicious_still_blocked_without_asking(env):
    guard, qb, sonarr, _ = env
    qb.add("lll", "Show.S01E09", [("Show.S01E09.mkv.exe", 400 * MB)])
    await guard.poll()
    assert not guard.store.pending_decisions()
    assert qb.called("/torrents/delete")
