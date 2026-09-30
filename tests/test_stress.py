"""Randomised whole-pipeline stress: many torrents at once, racing hooks, ClamAV outages, category changes."""

import asyncio
import logging
import random
import time
import zipfile
from urllib.parse import parse_qs

import httpx
import pytest

from protectarr.clamav import ClamdClient
from conftest import EICAR, MKV, PE
from test_guard import FakeQbit
from test_integrations import stack  # noqa: F401

MB = 1024 * 1024
KINDS = ["good", "good", "good", "exe_name", "pe_as_mkv", "eicar_srt", "tiny", "pw_zip", "good_album"]
BAD = {"exe_name", "pe_as_mkv", "eicar_srt", "pw_zip"}
SUSPICIOUS = {"tiny"}


class LiveQbit(FakeQbit):
    """FakeQbit whose stop/start change the state, like the real thing."""

    def handler(self, request):
        path = request.url.path.removeprefix("/api/v2")
        if request.method == "POST" and path in ("/torrents/stop", "/torrents/start"):
            form = parse_qs(request.content.decode())
            t = self.torrents.get(form["hashes"][0])
            if t:
                done = t["progress"] >= 1
                t["state"] = ("stoppedUP" if done else "stoppedDL") if path.endswith("stop") else \
                    ("stalledUP" if done else "downloading")
        return super().handler(request)


class Clamd:
    """In-process clamd that can be taken down and brought back."""

    def __init__(self):
        self.up = True

    async def start(self):
        async def handle(reader, writer):
            try:
                cmd = await reader.readuntil(b"\0")
                if not self.up:
                    writer.close()
                    return
                if cmd == b"zPING\0":
                    writer.write(b"PONG\0")
                else:
                    data = b""
                    while n := int.from_bytes(await reader.readexactly(4), "big"):
                        data += await reader.readexactly(n)
                    writer.write(b"stream: Eicar FOUND\0" if b"EICAR" in data else b"stream: OK\0")
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            writer.close()
        self.server = await asyncio.start_server(handle, "127.0.0.1", 0)
        return ClamdClient("127.0.0.1", self.server.sockets[0].getsockname()[1], 5)


def plan(i, kind):
    """(qBittorrent file list, {relative path: bytes on disk}, category)."""
    n = f"Show{i}.S01E01"
    if kind == "good":
        return [(f"{n}/{n}.mkv", 400 * MB), (f"{n}/{n}.srt", 50)], \
            {f"{n}/{n}.mkv": MKV, f"{n}/{n}.srt": b"1\n00:00:01,000 --> 00:00:02,000\nhi\n"}, "tv-sonarr"
    if kind == "good_album":
        files = {f"Album{i}/{t:02}.flac": b"fLaC" + b"\0" * 200 for t in range(8)}
        return [(k, 30 * MB) for k in files], files, "music"
    if kind == "exe_name":
        return [(f"{n}/{n}.mkv.exe", 400 * MB)], {f"{n}/{n}.mkv.exe": PE}, "tv-sonarr"
    if kind == "pe_as_mkv":
        return [(f"{n}/{n}.mkv", 400 * MB)], {f"{n}/{n}.mkv": PE + b"\0" * 2000}, "tv-sonarr"
    if kind == "eicar_srt":
        return [(f"{n}/{n}.mkv", 400 * MB), (f"{n}/{n}.srt", 68)], \
            {f"{n}/{n}.mkv": MKV, f"{n}/{n}.srt": EICAR}, "tv-sonarr"
    if kind == "tiny":
        return [(f"{n}/{n}.mkv", 2 * MB)], {f"{n}/{n}.mkv": MKV}, "tv-sonarr"
    if kind == "pw_zip":
        return [(f"{n}/{n}.mkv", 400 * MB), (f"{n}/extras.zip", 4000)], {f"{n}/{n}.mkv": MKV}, "tv-sonarr"
    raise ValueError(kind)


def write_zip_encrypted(path):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("setup.txt", b"x")
    raw = bytearray(path.read_bytes())
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = raw.find(sig)
        while i != -1:
            raw[i + off] |= 1
            i = raw.find(sig, i + 4)
    path.write_bytes(bytes(raw))


@pytest.mark.parametrize("seed", [1, 2, 3])
async def test_chaos(stack, seed, caplog):
    caplog.set_level(logging.ERROR)
    rng = random.Random(seed)
    guard, _, sonarr, lidarr, tmp = stack
    qb = LiveQbit()
    guard.qbit.http._transport = httpx.MockTransport(qb.handler)
    clamd = Clamd()
    guard.scanner.clamd = await clamd.start()
    await guard.refresh_categories()
    dl = tmp / "dl"
    torrents = {}
    for i in range(150):
        kind = rng.choice(KINDS)
        files, disk, cat = plan(i, kind)
        h = f"{rng.getrandbits(160):040x}"
        torrents[h] = (kind, disk)
        qb.add(h, f"T{i}", files, state="stoppedDL" if rng.random() < .5 else "metaDL", category=cat)
        qb.torrents[h]["added_on"] = time.time()
        qb.pieces[h] = [0] * 8

    async def hooks():
        for _ in range(300):
            await guard.process_hash(rng.choice(list(torrents)))
            await asyncio.sleep(0)

    async def world():
        for tick in range(60):
            clamd.up = not (20 <= tick < 30)  # a ClamAV outage in the middle
            for h, (kind, disk) in torrents.items():
                t = qb.torrents.get(h)
                if not t:
                    continue
                if t["state"] == "metaDL" and rng.random() < .5:
                    t["state"] = "stoppedDL"  # metadata arrived; stop condition applied
                if t["state"] == "downloading" and rng.random() < .3:
                    for rel, data in disk.items():
                        p = dl / rel
                        p.parent.mkdir(parents=True, exist_ok=True)
                        if not p.exists():
                            if rel.endswith("extras.zip"):
                                write_zip_encrypted(p)
                            else:
                                p.write_bytes(data)
                    for f in qb.files[h]:
                        f["progress"] = 1.0
                    qb.pieces[h] = [2] * 8
                    t.update(progress=1.0, state="stalledUP")
                    if t["category"] == "tv-sonarr" and rng.random() < .3:
                        t["category"] = "done"  # the *arr's category after import
            await guard.poll()
            await asyncio.sleep(0.01)

    await asyncio.wait_for(asyncio.gather(world(), hooks()), 120)
    clamd.up = True
    for _ in range(5):
        await guard.poll()
        await guard.drain()
    await guard.recheck_unscanned()
    for _ in range(3):
        await guard.poll()
        await guard.drain()
    clamd.server.close()

    held = {d["hash"] for d in guard.store.pending_decisions()}
    problems = []
    for h, (kind, disk) in torrents.items():
        row = guard.store.torrent(h)
        blocked = guard.store.is_blocked(h)
        t = qb.torrents.get(h)
        finished = t is None or t["progress"] >= 1
        if kind in BAD:
            ok = blocked or h in held or (not finished and (row is None or row["content_level"] is None))
            # a bad release that finished must never be sitting in the download folder as clean
            if finished and row is not None and row["content_level"] in ("clean",) and not blocked:
                ok = False
        elif kind in SUSPICIOUS:
            ok = h in held or blocked or row is None
        else:
            ok = not blocked and (h not in held)
            if finished and t and row is not None and row["content_level"] not in ("clean", "allowed", None):
                ok = False
        if not ok:
            problems.append((kind, row["content_level"] if row else None, blocked, h in held, t and t["state"],
                             [e["action"] for e in guard.store.events(2000) if e["hash"] == h]))
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert not problems, problems[:5]
    assert not errors, errors[:5]
