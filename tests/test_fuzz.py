"""Random and mangled input: names, file headers and archives must never crash a check."""

import io
import os
import random
import tempfile
import zipfile

from protectarr.filetype import sniff_bytes
from protectarr.rules import TorrentFile, check_metadata, extension
from protectarr.scanner import Scanner
from protectarr import archives

ALPH = "abc.XYZ /\\\u202e\u2067\u200b\u00e9\u4e2d\U0001f600 \t\n.mkv.exe..\x00-_"


def rname(rng):
    return "".join(rng.choice(ALPH) for _ in range(rng.randint(0, 40)))


def test_rules_never_crash():
    rng = random.Random(7)
    for _ in range(5000):
        files = [TorrentFile(rname(rng), rng.randint(-5, 10**12)) for _ in range(rng.randint(0, 6))]
        for prof in ("tv", "movie", "music", "book", "weird"):
            check_metadata(files, rng.randint(0, 10**9), rng.random() < .5, [rname(rng)], prof)


def test_sniff_never_crashes():
    rng = random.Random(8)
    for _ in range(20000):
        sniff_bytes(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 1100))))


async def test_scanner_on_random_and_mangled_files(tmp_path):
    rng = random.Random(9)
    s = Scanner(None, 25 * 1024 * 1024)
    good = io.BytesIO()
    with zipfile.ZipFile(good, "w") as z:
        z.writestr("a.mkv", b"x" * 100)
        z.writestr("../../evil.exe", b"MZ")
    heads = [b"PK\x03\x04", b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00", b"7z\xbc\xaf\x27\x1c", b"MZ",
             b"\x1a\x45\xdf\xa3", b""]
    for i in range(300):
        base = good.getvalue() if rng.random() < .3 else rng.choice(heads) + os.urandom(rng.randint(0, 3000))
        data = bytearray(base)
        for _ in range(rng.randint(0, 20)):
            if data:
                data[rng.randrange(len(data))] = rng.getrandbits(8)
        name = rng.choice(["x.zip", "x.rar", "x.7z", "x.mkv", "x.cbz", "x.epub", "x.srt", "x"])
        p = tmp_path / f"{i}{name}"
        p.write_bytes(bytes(data))
        await s.scan([(name, str(p))], rng.choice(["tv", "book", "music"]))


def test_zip_path_traversal_entry_is_reported():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../evil.exe", b"MZ")
    with tempfile.NamedTemporaryFile(suffix=".zip") as f:
        f.write(buf.getvalue())
        f.flush()
        info = archives.inspect(f.name, "zip")
    assert any(extension(e) == ".exe" for e in info.entries)
