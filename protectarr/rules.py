"""Metadata-stage checks: file names and sizes, run before any content downloads."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .findings import Level, Verdict

VIDEO_EXT = {".mkv", ".mp4", ".m4v", ".avi", ".ts", ".m2ts", ".mov", ".webm", ".mpg", ".mpeg", ".vob"}
AUDIO_EXT = {".flac", ".mp3", ".m4a", ".m4b", ".aac", ".ogg", ".oga", ".opus", ".wav", ".aiff", ".aif", ".ape", ".wv",
             ".alac", ".dsf", ".dff", ".wma", ".mka"}
BOOK_EXT = {".epub", ".mobi", ".azw", ".azw3", ".kfx", ".pdf", ".cbz", ".cbr", ".cb7", ".djvu", ".fb2", ".lit"}
# Old "you need a codec / license to play this" lures. Rare in genuine modern releases.
LEGACY_VIDEO_EXT = {".wmv", ".asf"}
SIDECAR_EXT = {
    ".srt", ".ass", ".ssa", ".sub", ".idx", ".sup", ".vtt", ".smi",
    ".nfo", ".txt", ".jpg", ".jpeg", ".png", ".webp", ".sfv", ".md5", ".sha1", ".sha256",
}
EXECUTABLE_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".msi", ".msp", ".lnk", ".jar", ".dll", ".cpl", ".reg", ".inf",
    ".app", ".dmg", ".pkg", ".sh", ".run", ".bin", ".desktop", ".apk", ".appimage", ".command",
}
LURE_EXT = {".url", ".html", ".htm", ".website", ".webloc", ".pdf", ".docx", ".doc"}
# Extra files that are normal in music releases (cue sheets, rip logs, playlists, booklets).
MUSIC_SIDECAR_EXT = {".cue", ".log", ".m3u", ".m3u8", ".accurip", ".pdf", ".md5", ".ffp"} | VIDEO_EXT
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".arj"}
DISK_IMAGE_EXT = {".iso", ".img", ".vhd", ".vhdx"}
RTLO = "‮"
LURE_WORDS = ("codec", "password", "passwd", "keygen", "crack", "player_setup", "watch online", "install")


@dataclass(frozen=True)
class TorrentFile:
    name: str  # path relative to the torrent root
    size: int


def extension(name: str) -> str:
    return PurePosixPath(name.lower()).suffix


def is_split_rar(ext: str) -> bool:
    # .r00, .r01 ... and .001, .002 parts of split archives
    return len(ext) == 4 and ext[1] in "r0" and ext[2:].isdigit()


def is_sample(name: str) -> bool:
    parts = PurePosixPath(name.lower()).parts
    return any(p in ("sample", "samples") for p in parts[:-1]) or "sample" in PurePosixPath(parts[-1]).stem.split(".")


_MEDIA_WORD = {**{e: "a video" for e in VIDEO_EXT | LEGACY_VIDEO_EXT}, **{e: "an audio file" for e in AUDIO_EXT},
               **{e: "a book" for e in BOOK_EXT}}
# What the main files of each profile look like, and what a release with none of them is called.
MAIN_EXT = {"tv": VIDEO_EXT, "movie": VIDEO_EXT, "music": AUDIO_EXT, "book": BOOK_EXT | AUDIO_EXT}
MISSING = {"tv": "no video file", "movie": "no video file", "music": "no audio file", "book": "no book or audiobook file"}


def check_metadata(files: list[TorrentFile], min_video_bytes: int, allow_archives: bool = False,
                   extra_blocked: list[str] | None = None, profile: str = "tv") -> Verdict:
    """Check a torrent's file names and sizes. profile: tv | movie | music | book."""
    v = Verdict()
    blocked = EXECUTABLE_EXT | {e.lower() if e.startswith(".") else "." + e.lower() for e in (extra_blocked or [])}
    video = profile in ("tv", "movie")
    main_ext = MAIN_EXT.get(profile, VIDEO_EXT)
    sidecar_ext = SIDECAR_EXT | (MUSIC_SIDECAR_EXT if profile == "music" else set())
    main_videos: list[TorrentFile] = []
    has_archive = False

    for f in files:
        name = f.name
        base = PurePosixPath(name).name
        ext = extension(name)
        lower = base.lower()

        if RTLO in name:
            v.add(Level.MALICIOUS, "rtlo", f"hidden right-to-left character disguises the real extension of '{base}'", name)
            continue
        if ext in blocked:
            suffixes = [s.lower() for s in PurePosixPath(lower).suffixes]
            fake = next((_MEDIA_WORD[s] for s in suffixes[:-1] if s in _MEDIA_WORD), None)
            if len(suffixes) > 1 and fake:
                v.add(Level.MALICIOUS, "double_extension", f"'{base}' pretends to be {fake} but is a {ext} program", name)
            else:
                v.add(Level.MALICIOUS, "executable", f"program file '{base}' in a media release", name)
            continue
        if ext in main_ext:
            if not is_sample(name):
                main_videos.append(f)
            continue
        if ext in sidecar_ext:
            if any(w in lower for w in LURE_WORDS):
                v.add(Level.SUSPICIOUS, "lure_name", f"'{base}' looks like a password or codec lure", name)
            continue
        if video and ext in LEGACY_VIDEO_EXT:
            v.add(Level.SUSPICIOUS, "legacy_video", f"'{base}' is WMV/ASF, a format used by codec-download lures", name)
            main_videos.append(f)
            continue
        if ext in ARCHIVE_EXT or is_split_rar(ext):
            has_archive = True
            if not allow_archives:
                v.add(Level.SUSPICIOUS, "archive", f"archive '{base}' in a media release", name)
            continue
        if ext in DISK_IMAGE_EXT:
            v.add(Level.SUSPICIOUS, "disk_image", f"disk image '{base}' in a media release", name)
            continue
        if ext in LURE_EXT:
            v.add(Level.SUSPICIOUS, "lure_file", f"link or document '{base}' is a common scam lure", name)
            continue
        v.add(Level.SUSPICIOUS, "unknown_type", f"unexpected file type '{base}'", name)

    if not main_videos:
        # An allowed archive release carries its media inside the archive.
        if not (allow_archives and has_archive):
            v.add(Level.SUSPICIOUS, "no_video" if video else "no_media", f"{MISSING.get(profile, 'no media file')} in the release")
    elif video:
        largest = max(main_videos, key=lambda f: f.size)
        if largest.size < min_video_bytes:
            v.add(Level.SUSPICIOUS, "too_small",
                  f"largest video is {largest.size / 1048576:.1f} MB, below the {min_video_bytes // 1048576} MB minimum",
                  largest.name)
    return v
