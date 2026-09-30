import pytest

from protectarr.filetype import sniff, sniff_bytes


@pytest.mark.parametrize("head,kind", [
    (b"MZ\x90\x00" + b"\0" * 60, "pe"),
    (b"\x7fELF\x02\x01", "elf"),
    (b"#!/bin/sh\n", "script"),
    (b"L\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 8, "lnk"),
    (b"\x1a\x45\xdf\xa3" + b"\0" * 20, "matroska"),
    (b"\x00\x00\x00\x20ftypisom", "mp4"),
    (b"RIFF\x00\x00\x00\x00AVI LIST", "avi"),
    (b"\x47" + b"\0" * 187 + b"\x47" + b"\0" * 10, "mpeg_ts"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07\x01\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"<!DOCTYPE html><html>", "html"),
    (b"[InternetShortcut]\nURL=http://x", "url_shortcut"),
    (b"Good subtitles", "unknown"),
])
def test_sniff_bytes(head, kind):
    assert sniff_bytes(head) == kind


def test_sniff_iso(tmp_path):
    p = tmp_path / "x.iso"
    p.write_bytes(b"\0" * 0x8001 + b"CD001" + b"\0" * 100)
    assert sniff(p) == "iso"


def test_sniff_empty(tmp_path):
    p = tmp_path / "e"
    p.write_bytes(b"")
    assert sniff(p) == "empty"
