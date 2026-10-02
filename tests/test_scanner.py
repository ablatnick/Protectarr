import asyncio
import struct

import pytest

from protectarr.clamav import ClamdClient, parse_reply
from protectarr.findings import Level
from protectarr.scanner import Scanner
from conftest import EICAR, MKV, PE, make_zip

MB = 1024 * 1024


@pytest.fixture
async def fake_clamd():
    async def handle(reader, writer):
        cmd = await reader.readuntil(b"\0")
        if cmd == b"zPING\0":
            writer.write(b"PONG\0")
        else:
            data = b""
            while True:
                (n,) = struct.unpack("!L", await reader.readexactly(4))
                if n == 0:
                    break
                data += await reader.readexactly(n)
            writer.write(b"stream: Eicar-Test-Signature FOUND\0" if EICAR in data else b"stream: OK\0")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield ClamdClient("127.0.0.1", port, timeout=5)
    server.close()


def write(tmp_path, name, data):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return (name, str(p))


def codes(v):
    return {f.code for f in v.findings}


async def test_real_video_is_clean(tmp_path, fake_clamd):
    v = await Scanner(fake_clamd, 25 * MB).scan([write(tmp_path, "M/movie.mkv", MKV)])
    assert v.level == Level.CLEAN


async def test_program_disguised_as_video(tmp_path):
    v = await Scanner(None, 25 * MB).scan([write(tmp_path, "M/movie.mkv", PE)])
    assert v.level == Level.MALICIOUS and "hidden_executable" in codes(v)


async def test_zip_disguised_as_video(tmp_path):
    f = write(tmp_path, "movie.mp4", b"")
    make_zip(f[1], {"movie.mp4.exe": PE})
    v = await Scanner(None, 25 * MB).scan([f])
    assert {"disguised_archive", "archive_executable"} <= codes(v)


async def test_password_zip(tmp_path):
    f = write(tmp_path, "movie.zip", b"")
    make_zip(f[1], {"movie.mkv": MKV}, encrypted=True)
    v = await Scanner(None, 25 * MB, allow_archives=True).scan([f])
    assert v.level == Level.MALICIOUS and "password_archive" in codes(v)


async def test_subtitle_that_is_a_web_page(tmp_path):
    v = await Scanner(None, 25 * MB).scan([write(tmp_path, "subs.srt", b"<html><script>")])
    assert "disguised_lure" in codes(v)


async def test_clamav_detection(tmp_path, fake_clamd):
    v = await Scanner(fake_clamd, 25 * MB).scan([write(tmp_path, "readme.txt", EICAR)])
    assert v.level == Level.MALICIOUS and "clamav" in codes(v)
    assert await fake_clamd.ping()


async def test_clamav_down_is_not_clean(tmp_path):
    v = await Scanner(ClamdClient("127.0.0.1", 1, timeout=1), 25 * MB).scan([write(tmp_path, "a.txt", b"hi")])
    assert v.level == Level.SUSPICIOUS and "clamav_unavailable" in codes(v)


def test_parse_reply():
    assert parse_reply("stream: Win.Trojan.X-1 FOUND").signature == "Win.Trojan.X-1"
    assert not parse_reply("stream: OK").infected
    assert parse_reply("INSTREAM size limit exceeded. ERROR").error


async def test_allowed_extension_still_checks_contents(tmp_path, fake_clamd):
    s = Scanner(fake_clamd, 25 * MB, allowed_extensions=[".exe", ".zip", ".srt"])
    assert (await s.scan([write(tmp_path, "tool.exe", PE)])).level == Level.CLEAN
    z = write(tmp_path, "extras.zip", b"")
    make_zip(z[1], {"setup.exe": PE, "inner.zip": b"x"})
    assert (await s.scan([z])).level == Level.CLEAN  # allowed types inside an allowed archive
    make_zip(z[1], {"setup.exe": PE, "inner.rar": b"x", "run.bat": b"x"})
    assert {"archive_nested", "archive_executable"} <= codes(await s.scan([z]))
    assert "hidden_executable" in codes(await s.scan([write(tmp_path, "subs.srt", PE)]))
    assert "clamav" in codes(await s.scan([write(tmp_path, "virus.exe", PE + EICAR)]))
    p = write(tmp_path, "locked.zip", b"")
    make_zip(p[1], {"m.mkv": MKV}, encrypted=True)
    assert "password_archive" in codes(await s.scan([p]))
