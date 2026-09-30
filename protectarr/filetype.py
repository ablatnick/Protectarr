"""Identify a file's real type from its first bytes, regardless of its extension."""

from __future__ import annotations

from pathlib import Path

EXECUTABLE_KINDS = {"pe", "elf", "macho", "script", "lnk", "msi_ole", "java_class"}
ARCHIVE_KINDS = {"zip", "rar", "7z", "gzip", "bzip2", "xz", "cab"}
VIDEO_KINDS = {"matroska", "mp4", "avi", "mpeg_ts", "mpeg_ps", "asf", "flv"}
AUDIO_KINDS = {"flac", "mp3", "ogg", "wav", "aiff", "ape", "wavpack", "dsf", "mp4", "asf", "matroska"}
MEDIA_KINDS = VIDEO_KINDS | AUDIO_KINDS

# Which real kinds are acceptable for each extension.
EXPECTED = {
    ".mkv": {"matroska"}, ".webm": {"matroska"},
    ".mp4": {"mp4"}, ".m4v": {"mp4"}, ".mov": {"mp4"},
    ".avi": {"avi"},
    ".ts": {"mpeg_ts"}, ".m2ts": {"mpeg_ts"},
    ".mpg": {"mpeg_ps", "mpeg_ts"}, ".mpeg": {"mpeg_ps", "mpeg_ts"}, ".vob": {"mpeg_ps"},
    ".wmv": {"asf"}, ".asf": {"asf"},
    ".zip": {"zip"}, ".rar": {"rar"}, ".7z": {"7z"},
    ".flac": {"flac", "mp3"},  # some taggers put an ID3 header in front of FLAC
    ".mp3": {"mp3"}, ".ogg": {"ogg"}, ".oga": {"ogg"}, ".opus": {"ogg"}, ".wav": {"wav"},
    ".aiff": {"aiff"}, ".aif": {"aiff"}, ".ape": {"ape"}, ".wv": {"wavpack"}, ".dsf": {"dsf"},
    ".m4a": {"mp4"}, ".m4b": {"mp4"}, ".mka": {"matroska"}, ".wma": {"asf"},
    # Comic files are very often a zip named .cbr or the other way round.
    ".epub": {"zip"}, ".cbz": {"zip", "rar"}, ".cbr": {"rar", "zip"}, ".cb7": {"7z"}, ".pdf": {"pdf"},
    ".mobi": {"mobi"}, ".azw": {"mobi"}, ".azw3": {"mobi"},
}
# Book formats that are archives by design: their contents are still checked, but they aren't "an archive".
CONTAINER_EXT = {".epub", ".cbz", ".cbr", ".cb7"}

_MACHO = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}


def sniff_bytes(head: bytes) -> str:
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in _MACHO:
        # 0xCAFEBABE is shared by Java classes and fat Mach-O binaries; both are executable.
        return "macho"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "msi_ole"
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        return "matroska"
    if len(head) >= 12 and head[4:8] in (b"ftyp", b"moov", b"mdat", b"free", b"wide", b"skip", b"pnot", b"uuid"):
        return "mp4"
    if head.startswith(b"RIFF") and head[8:12] == b"AVI ":
        return "avi"
    if head.startswith(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11"):
        return "asf"
    if head.startswith(b"FLV"):
        return "flv"
    if head.startswith((b"\x00\x00\x01\xba", b"\x00\x00\x01\xb3")):  # program stream, MPEG-1 video
        return "mpeg_ps"
    if len(head) >= 189 and head[:1] == b"\x47" and head[188:189] == b"\x47":
        return "mpeg_ts"
    if len(head) >= 196 and head[4:5] == b"\x47" and head[196:197] == b"\x47":
        return "mpeg_ts"  # M2TS: 4-byte timestamp before each 188-byte packet
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"MSCF"):
        return "cab"
    if b"%PDF-" in head[:512]:  # readers accept some bytes before the header
        return "pdf"
    if head.startswith(b"fLaC"):
        return "flac"
    if head.startswith(b"ID3") or (len(head) > 1 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
        return "mp3"
    if head.startswith(b"OggS"):
        return "ogg"
    if head[:4] in (b"RIFF", b"RF64", b"BW64") and head[8:12] == b"WAVE":  # RF64/BW64: WAVs over 4 GB
        return "wav"
    if head.startswith(b"FORM") and head[8:12] in (b"AIFF", b"AIFC"):
        return "aiff"
    if head.startswith(b"MAC "):
        return "ape"
    if head.startswith(b"wvpk"):
        return "wavpack"
    if head.startswith(b"DSD "):
        return "dsf"
    if head[60:68] in (b"BOOKMOBI", b"TEXtREAd"):
        return "mobi"
    ts = _ts_offset(head)
    if ts is not None:
        return "mpeg_ts"  # a recording cut mid-packet: the packets start a little way in
    padded = head.lstrip(b"\0")
    if 0 < len(padded) < len(head) and (padded.startswith(b"ID3") or (len(padded) > 1 and padded[0] == 0xFF
                                                                     and padded[1] & 0xE0 == 0xE0)):
        return "mp3"  # some encoders pad the start with zeros
    stripped = head.lstrip().lower()
    if stripped.startswith((b"<!doctype html", b"<html", b"<script")):
        return "html"
    if stripped.startswith(b"[internetshortcut]"):
        return "url_shortcut"
    return "unknown"


def _ts_offset(head: bytes) -> int | None:
    """Where MPEG-TS packets (0x47 every 188 bytes, three in a row) start in the first packet's worth of bytes."""
    for i in range(min(188, len(head) - 376)):
        if head[i] == 0x47 and head[i + 188] == 0x47 and head[i + 376] == 0x47:
            return i
    return None


def sniff(path: str | Path) -> str:
    with open(path, "rb") as fh:
        head = fh.read(1024)
    if not head:
        return "empty"
    kind = sniff_bytes(head)
    if kind == "unknown" and _has_iso9660(path):
        return "iso"
    return kind


def _has_iso9660(path: str | Path) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.seek(0x8001)
            return fh.read(5) == b"CD001"
    except OSError:
        return False
