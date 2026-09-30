"""Failure modes found by stress testing: every way a bad file could slip through, and the false alarms."""

import asyncio
import io
import os
import stat
import time
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

from protectarr.clamav import ClamdClient
from protectarr.filetype import sniff_bytes
from protectarr.findings import Level
from protectarr.guard import Guard
from protectarr.quarantine import HELD_SUFFIX, Quarantine
from protectarr.rules import TorrentFile, check_metadata
from protectarr.scanner import Scanner
from protectarr.web import create_app
from conftest import EICAR, MKV, PE
from test_integrations import FakeArr, ImportedSonarr, stack  # noqa: F401

MB = 1024 * 1024


def put(tmp, rel, data):
    f = tmp / "dl" / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(data)
    return f


async def ready(guard):
    await guard.refresh_categories()
    guard.background_scans = False


def restarted(guard):
    """A new Guard on the same database, as after a container restart."""
    return Guard(guard.cfg, guard.store, guard.qbit, guard.arrs, guard.scanner, guard.quarantine)


async def fake_clamd(infected=b""):
    """A clamd that answers INSTREAM with OK, or FOUND when the stream contains `infected`."""
    async def handle(reader, writer):
        cmd = await reader.readuntil(b"\0")
        if cmd == b"zPING\0":
            writer.write(b"PONG\0")
        else:
            data = b""
            while n := int.from_bytes(await reader.readexactly(4), "big"):
                data += await reader.readexactly(n)
            writer.write(b"stream: Eicar-Test FOUND\0" if infected and infected in data else b"stream: OK\0")
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, ClamdClient("127.0.0.1", server.sockets[0].getsockname()[1], 5)


# ----- nothing unchecked passes as clean ---------------------------------------------------------------------

async def test_files_not_found_are_held_not_passed(stack):
    """Wrong PATH_MAPPINGS or a missing mount: the files can't be seen, so the download can't be called clean."""
    guard, qb, _, _, tmp = stack
    await ready(guard)
    guard.cfg.path_mappings = []  # qBittorrent says /downloads, which doesn't exist in here
    qb.add("pm1", "Show.S01E01", [("Show.S01E01.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    for _ in range(3):
        await guard.poll()
    assert guard.store.torrent("pm1")["content_level"] == "held"
    [d] = guard.store.pending_decisions()
    assert "PATH_MAPPINGS" in d["summary"]


async def test_clamav_outage_holds_then_releases_when_it_is_back(stack):
    guard, qb, _, _, tmp = stack
    await ready(guard)
    guard.scanner.clamd = ClamdClient("127.0.0.1", 1, timeout=1)  # down
    f = put(tmp, "Show.S01E02/Show.S01E02.mkv", MKV)
    put(tmp, "Show.S01E02/Show.S01E02.srt", b"1\n00:00:01,000 --> 00:00:02,000\nHi\n")
    qb.add("cd1", "Show.S01E02", [("Show.S01E02/Show.S01E02.mkv", 400 * MB), ("Show.S01E02/Show.S01E02.srt", 60)],
           state="stalledUP", progress=1.0)
    await guard.poll()
    [d] = guard.store.pending_decisions()
    assert d["findings"][0]["code"] == "clamav_unavailable" and not f.exists()  # locked away meanwhile

    server, guard.scanner.clamd = await fake_clamd()
    await guard.recheck_unscanned()
    server.close()
    assert not guard.store.pending_decisions() and f.exists()
    assert "released automatically" in guard.store.events()[0]["action"]


async def test_clamav_outage_then_infected_is_blocked_automatically(stack):
    guard, qb, _, _, tmp = stack
    await ready(guard)
    guard.scanner.clamd = ClamdClient("127.0.0.1", 1, timeout=1)
    put(tmp, "Show.S01E03/Show.S01E03.mkv", MKV)
    put(tmp, "Show.S01E03/Show.S01E03.srt", EICAR)
    qb.add("cd2", "Show.S01E03", [("Show.S01E03/Show.S01E03.mkv", 400 * MB), ("Show.S01E03/Show.S01E03.srt", 68)],
           state="stalledUP", progress=1.0)
    await guard.poll()
    server, guard.scanner.clamd = await fake_clamd(infected=b"EICAR")
    await guard.recheck_unscanned()
    server.close()
    assert guard.store.is_blocked("cd2") and "blocked automatically" in guard.store.events()[0]["action"]


async def test_quarantine_folder_unusable_locks_files_in_place(stack):
    """Quarantine can't be written (full disk, wrong owner): the file is renamed so no *arr app imports it."""
    guard, qb, _, _, tmp = stack
    await ready(guard)
    guard.cfg.actions["malicious"] = "hold"
    guard.quarantine.fallback_root = tmp / "cfg" / "quarantine-records"  # as the service sets it up
    qdir = tmp / "q"
    qdir.mkdir()
    os.chmod(qdir, stat.S_IRUSR | stat.S_IXUSR)
    try:
        f = put(tmp, "Show.S01E04.mkv", PE)
        qb.add("qf1", "Show.S01E04", [("Show.S01E04.mkv", 400 * MB)], state="stalledUP", progress=1.0)
        await guard.poll()
        assert not f.exists() and (tmp / "dl" / ("Show.S01E04.mkv" + HELD_SUFFIX)).exists()
        [d] = guard.store.pending_decisions()
        await guard.allow(d["id"])
        assert f.read_bytes() == PE  # and allowing puts it back
    finally:
        os.chmod(qdir, 0o755)


async def test_quarantine_failure_while_blocking_still_removes_the_files(stack, monkeypatch):
    guard, qb, _, _, tmp = stack
    await ready(guard)

    def broken(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(guard.quarantine, "store", broken)
    put(tmp, "Show.S01E05.mkv", PE)
    qb.add("qf2", "Show.S01E05", [("Show.S01E05.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    await guard.poll()
    assert qb.called("/torrents/delete") == [{"hashes": "qf2", "deleteFiles": "true"}]
    assert "could not quarantine" in guard.store.events()[0]["action"]


def test_half_finished_move_is_rolled_back(tmp_path, monkeypatch):
    """A move that fails part-way puts back the files that already moved, then locks them in place."""
    import shutil
    a, b = tmp_path / "dl" / "a.mkv", tmp_path / "dl" / "b.mkv"
    a.parent.mkdir()
    a.write_bytes(b"A")
    b.write_bytes(b"B")
    real, calls = shutil.move, []

    def flaky(src, dst):
        calls.append(src)
        if len(calls) == 2:
            raise OSError(28, "No space left on device")
        return real(src, dst)
    monkeypatch.setattr(shutil, "move", flaky)
    q = Quarantine(str(tmp_path / "q"))
    qid = q.store("h" * 40, "x", [("a.mkv", str(a)), ("b.mkv", str(b))], {})
    assert [f["in_place"] for f in q.record(qid)["files"]] == [True, True]
    monkeypatch.setattr(shutil, "move", real)
    q.restore(qid)
    assert a.read_bytes() == b"A" and b.read_bytes() == b"B"


async def test_failed_removal_is_retried_not_recorded_clean(stack):
    guard, qb, _, _, tmp = stack
    await ready(guard)
    real, fails = qb.handler, {"n": 1}

    def flaky(request):
        if request.url.path.endswith("/torrents/delete") and fails["n"]:
            fails["n"] -= 1
            return httpx.Response(500, text="boom")
        return real(request)
    guard.qbit.http._transport = httpx.MockTransport(flaky)
    put(tmp, "Show.S01E06.mkv", PE)
    qb.add("df1", "Show.S01E06", [("Show.S01E06.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    await guard.poll()
    assert guard.store.is_blocked("df1") and "COULD NOT remove" in guard.store.events()[0]["action"]
    guard._blocked_at["df1"] = time.monotonic() - 200
    await guard.poll()
    assert "df1" not in qb.torrents and guard.store.torrent("df1")["content_level"] == "malicious"


# ----- torrents that leave the watched path ------------------------------------------------------------------

async def test_category_after_import_does_not_skip_the_scan(stack):
    """The *arr app's "category after import" moves the torrent out of the watched category first."""
    guard, qb, _, _, tmp = stack
    await ready(guard)
    qb.add("pi1", "Show.S01E07", [("Show.S01E07.mkv", 400 * MB)])
    await guard.poll()
    put(tmp, "Show.S01E07.mkv", PE)
    qb.torrents["pi1"].update(state="stalledUP", progress=1.0, category="done")
    await guard.poll()
    assert guard.store.is_blocked("pi1")


async def test_held_torrent_started_by_someone_else_is_stopped_again(stack):
    guard, qb, _, _, _ = stack
    await ready(guard)
    qb.add("h1", "Show.S01E08", [("Show.S01E08/Show.S01E08.wmv", 400 * MB)], state="stoppedDL")
    await guard.poll()
    stops = len(qb.called("/torrents/stop"))
    qb.torrents["h1"]["state"] = "downloading"  # somebody pressed Start
    await guard.poll()
    await guard.poll()
    assert len(qb.called("/torrents/stop")) == stops + 2
    assert sum("stopped again" in e["action"] for e in guard.store.events()) == 1  # logged once


# ----- *arr library clean-up only deletes what the bad release put there ---------------------------------------

async def test_readded_blocked_release_leaves_the_library_alone(stack):
    guard, qb, _, _, _ = stack
    sonarr = ImportedSonarr()
    sonarr.library = [{"id": 777, "path": "/tv/Show/Season 2/Show - S02E04.mkv"}]  # a good replacement
    guard.arrs[0].http._transport = httpx.MockTransport(sonarr.handler)
    await ready(guard)
    guard.store.block_hash("imp1", "Show.S02E04", "earlier")
    qb.add("imp1", "Show.S02E04", [("Show.S02E04/Show.S02E04.mkv", 400 * MB)])
    await guard.poll()
    assert sonarr.library and not sonarr.failed and "imp1" not in qb.torrents


class DatedSonarr(ImportedSonarr):
    def handler(self, request):
        r = super().handler(request)
        if request.url.path.endswith("/history"):
            body = r.json()
            body["records"][0]["date"] = "2026-09-01T10:00:00Z"
            return httpx.Response(200, json=body)
        return r


async def test_library_file_replaced_since_the_import_is_kept(stack):
    guard, qb, _, _, tmp = stack
    sonarr = DatedSonarr()
    sonarr.library = [{"id": 777, "path": "/tv/Show/Season 2/Show - S02E04.mkv", "dateAdded": "2026-09-20T08:00:00Z"}]
    guard.arrs[0].http._transport = httpx.MockTransport(sonarr.handler)
    await ready(guard)
    put(tmp, "Show.S02E04/Show.S02E04.mkv", PE)
    qb.add("imp1", "Show.S02E04", [("Show.S02E04/Show.S02E04.mkv", 400 * MB)], state="stalledUP", progress=1.0)
    await guard.poll()
    assert sonarr.library and sonarr.failed == [9000]
    action = guard.store.events()[0]["action"]
    assert "a later import replaced it" in action and "COULD NOT" not in action


# ----- restarts and outages -----------------------------------------------------------------------------------

async def test_restart_does_not_strand_a_checked_torrent(stack):
    guard, qb, _, _, _ = stack
    await ready(guard)
    qb.add("rs1", "Show.S03E01", [("Show.S03E01.mkv", 400 * MB)], state="downloading")
    await guard.poll()
    guard = restarted(guard)
    qb.torrents["rs1"]["state"] = "stoppedDL"  # the stop condition hit just as Protectarr went down
    await guard.poll()
    assert qb.called("/torrents/start") == [{"hashes": "rs1"}]


async def test_other_torrents_added_during_an_outage_are_started(stack):
    guard, qb, _, _, _ = stack
    await ready(guard)
    guard.store.set_setting("alive_at", time.time() - 900)  # Protectarr was down for 15 minutes
    guard = restarted(guard)
    qb.add("od1", "Linux.ISO", [("linux.iso", 3000 * MB)], category="linux", state="stoppedDL")
    qb.torrents["od1"]["added_on"] = time.time() - 600
    qb.add("od2", "Paused.On.Purpose", [("x.iso", 3000 * MB)], category="linux", state="stoppedDL")
    qb.torrents["od2"]["added_on"] = time.time() - 3600  # before the outage: left alone
    await guard.poll()
    assert qb.called("/torrents/start") == [{"hashes": "od1"}]


# ----- the poll loop is never blocked by scans --------------------------------------------------------------

async def test_long_scans_do_not_delay_new_torrents(stack):
    guard, qb, _, _, tmp = stack
    await guard.refresh_categories()
    server, guard.scanner.clamd = await fake_clamd()
    guard.scanner.scan_media = True
    real = guard.scanner.clamd.scan_file

    async def slow(path):
        await asyncio.sleep(0.2)
        return await real(path)
    guard.scanner.clamd.scan_file = slow
    tracks = [(f"Album/{i:02}.flac", 1000) for i in range(30)]
    qb.add("alb", "Album", tracks, category="music", progress=0.9)
    for i, (n, _) in enumerate(tracks):
        put(tmp, n, b"fLaC" + b"\0" * 996)
        qb.files["alb"][i]["progress"] = 1.0
    qb.add("bait", "Show.S09E09", [("Show.S09E09.mkv.exe", 400 * MB)])
    t = time.monotonic()
    await guard.poll()
    assert time.monotonic() - t < 1 and guard.store.is_blocked("bait")
    await guard.drain()
    server.close()


async def test_verified_media_is_not_sent_to_clamav_by_default(tmp_path):
    class Counting:
        calls = 0

        async def scan_file(self, path):
            Counting.calls += 1
    p = tmp_path / "01.flac"
    p.write_bytes(b"fLaC" + b"\0" * 100)
    v = await Scanner(Counting(), 25 * MB).scan([("01.flac", str(p))], "music")
    assert v.level == Level.CLEAN and Counting.calls == 0


# ----- file names Windows would run --------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "Setup.exe.", "Setup.exe ", "Setup.EXE", "Movie.mkv​.exe", "Codec.scf", "Play.chm", "Watch.one",
    "Player.msix", "Player.appx", "Play.xll", "Play.msc", "Play.vb", "Play.ws", "Play.settingcontent-ms",
    "Play.library-ms", "Play.xlsm", "Play.docm", "Play.py", "Play.pyw", "Play.gadget", "Play.hta ",
    "Movie⁧vkm.exe⁩.mkv", "Movie‫vkm.scr",
])
def test_windows_runnable_names_are_malicious(name):
    v = check_metadata([TorrentFile("Movie.2024/Movie.mkv", 2000 * MB), TorrentFile("Movie.2024/" + name, MB)],
                       300 * MB, profile="movie")
    assert v.level == Level.MALICIOUS, f"{name!r}: {v.summary()}"


@pytest.mark.parametrize("inner", ["payload.iso", "payload.img", "payload.vhd", "nested.zip", "Play.scf"])
async def test_allowed_archives_still_catch_what_hides_inside(tmp_path, inner):
    inner_zip = io.BytesIO()
    with zipfile.ZipFile(inner_zip, "w") as z:
        z.writestr("setup.exe", PE)
    p = tmp_path / "Movie.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("Movie.mkv", MKV)
        z.writestr(inner, inner_zip.getvalue() if inner.endswith(".zip") else b"\0" * 64)
    v = await Scanner(None, 25 * MB, allow_archives=True).scan([("Movie.zip", str(p))], "movie")
    assert v.level >= Level.SUSPICIOUS


# ----- false alarms on real releases ------------------------------------------------------------------------

@pytest.mark.parametrize("files,profile", [
    ([("M.2023.BluRay/BDMV/STREAM/00000.m2ts", 20000 * MB), ("M.2023.BluRay/BDMV/index.bdmv", 200),
      ("M.2023.BluRay/BDMV/MovieObject.bdmv", 200), ("M.2023.BluRay/BDMV/CLIPINF/00000.clpi", 200),
      ("M.2023.BluRay/BDMV/PLAYLIST/00000.mpls", 200), ("M.2023.BluRay/CERTIFICATE/id.bdmv", 200),
      ("M.2023.BluRay/BDMV/JAR/00000/menu.jar", 2 * MB), ("M.2023.BluRay/AACS/Unit_Key_RO.inf", 900),
      ("M.2023.BluRay/BDMV/META/DL/bdmt_eng.xml", 900)], "movie"),
    ([("M.2023.DVD/VIDEO_TS/VTS_01_1.VOB", 1000 * MB), ("M.2023.DVD/VIDEO_TS/VIDEO_TS.IFO", 20000),
      ("M.2023.DVD/VIDEO_TS/VIDEO_TS.BUP", 20000)], "movie"),
    ([("Album/01.flac", 30 * MB), ("Album/Scans/back.tif", 5 * MB), ("Album/Scans/cd.bmp", MB)], "music"),
    ([("Author - Book/Book.m4b", 300 * MB), ("Author - Book/metadata.opf", 3000)], "book"),
])
def test_real_releases_are_clean(files, profile):
    v = check_metadata([TorrentFile(n, s) for n, s in files], 300 * MB, profile=profile)
    assert v.level == Level.CLEAN, v.summary()


def test_jar_outside_a_disc_folder_is_still_a_program():
    v = check_metadata([TorrentFile("M/M.mkv", 2000 * MB), TorrentFile("M/JAR/menu.jar", MB)], 300 * MB,
                       profile="movie")
    assert v.level == Level.MALICIOUS


@pytest.mark.parametrize("ext,head", [
    (".wav", b"RF64\xff\xff\xff\xffWAVEds64" + b"\0" * 100),
    (".wav", b"BW64\xff\xff\xff\xffWAVEds64" + b"\0" * 100),
    (".mp3", b"\0" * 32 + b"\xff\xfb\x90\x64" + b"\0" * 400),
    (".ts", b"\0" * 50 + (b"\x47" + b"\0" * 187) * 4),
])
def test_real_media_variants_recognised(ext, head):
    v = Scanner(None, 25 * MB)._type_findings("x" + ext, ext, sniff_bytes(head))
    assert v.level == Level.CLEAN, v.summary()


def test_zero_padding_before_a_program_is_not_mp3():
    assert sniff_bytes(b"\0" * 16 + PE) == "unknown"


# ----- settings API -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    '{"arr": [{"url": "http://x", "api_key": "k"}]}', '{"clamav": null}', '{"qbittorrent": "nope"}',
    '{"arr": "sonarr"}',
    '{"clamav": {"port": 99999999}}', '[]', 'not json',
])
def test_settings_api_rejects_malformed_input(stack, body):
    guard = stack[0]
    c = TestClient(create_app(guard.cfg, guard, start_worker=False), raise_server_exceptions=False)
    r = c.post("/api/settings", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 400, f"{body} -> {r.status_code}"
