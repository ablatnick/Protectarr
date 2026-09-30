"""Completion-stage scan: real file types, archive contents and ClamAV."""

from __future__ import annotations

import asyncio
import os
from pathlib import PurePosixPath

from . import archives, filetype
from .clamav import ClamdClient
from .findings import Level, Verdict
from .rules import (ARCHIVE_EXT, AUDIO_EXT, DISK_IMAGE_EXT, EXECUTABLE_EXT, VIDEO_EXT, _disc_exception, extension,
                    in_disc_structure, is_split_rar)

LURE_KINDS = {"html": "web page", "url_shortcut": "internet shortcut", "pdf": "PDF document"}
# EPUB 3 books may legitimately carry JavaScript.
CONTAINER_ALLOWED = {".js"}


class FilesMissing(FileNotFoundError):
    """Downloaded files aren't where qBittorrent says they are (wrong path mapping or mount, or moved away)."""


class ClamavUnavailable(RuntimeError):
    """clamd couldn't scan a file that should be scanned (it's down, restarting or overloaded)."""


class Scanner:
    def __init__(self, clamd: ClamdClient | None, stream_max_bytes: int, allow_archives: bool = False,
                 scan_media: bool = False):
        self.clamd = clamd
        self.stream_max_bytes = stream_max_bytes
        self.allow_archives = allow_archives
        # Also send files that are verified real video/audio to ClamAV. Off: they're rarely the carrier, and an
        # album or season pack would otherwise keep ClamAV busy for minutes.
        self.scan_media = scan_media

    async def scan(self, files: list[tuple[str, str]], profile: str = "tv", clamav_required: bool = False) -> Verdict:
        """files: (display name relative to the torrent, local path) pairs of downloaded files.

        Raises FilesMissing when a file isn't on disk: a check that can't see the files must never pass them."""
        missing = [name for name, path in files if not os.path.isfile(path)]
        if missing:
            raise FilesMissing(f"{len(missing)} of {len(files)} file(s) not found where qBittorrent put them, e.g. "
                               f"'{next(p for n, p in files if n == missing[0])}'. Check PATH_MAPPINGS and that "
                               "Protectarr mounts the download folders at the same paths")
        v = Verdict()
        for name, path in files:
            v.extend(await self.scan_file(name, path, profile, clamav_required))
        return v

    async def sniff_partial(self, name: str, path: str) -> Verdict:
        """Check a file that is still downloading, from its first piece only: is it really what its name says?"""
        kind = await asyncio.to_thread(filetype.sniff, path)
        return self._type_findings(name, extension(name), kind)

    async def scan_file(self, name: str, path: str, profile: str = "tv", clamav_required: bool = False) -> Verdict:
        """clamav_required: raise ClamavUnavailable when ClamAV can't scan, instead of a finding."""
        ext = extension(name)
        kind = await asyncio.to_thread(filetype.sniff, path)
        v = self._type_findings(name, ext, kind)

        if kind in ("zip", "rar", "7z"):
            container = ((profile == "book" and ext in filetype.CONTAINER_EXT)
                         or (in_disc_structure(name) and _disc_exception(name, ext)))  # Blu-ray menu .jar
            v.extend(await asyncio.to_thread(self._check_archive, name, path, kind, container))

        # A file already known to be malicious needs no second opinion, and ClamAV can take a while.
        if v.level < Level.MALICIOUS:
            v.extend(await self._clamav(name, path, ext, kind, clamav_required))
        return v

    def _type_findings(self, name: str, ext: str, kind: str) -> Verdict:
        v = Verdict()
        base = PurePosixPath(name).name

        if kind in filetype.EXECUTABLE_KINDS:
            if ext in EXECUTABLE_EXT:
                v.add(Level.MALICIOUS, "executable", f"'{base}' is a program ({kind})", name)
            else:
                v.add(Level.MALICIOUS, "hidden_executable", f"'{base}' is really a program ({kind}) disguised as {ext or 'a file'}", name)
        elif ext in filetype.EXPECTED and kind not in filetype.EXPECTED[ext]:
            if kind in filetype.ARCHIVE_KINDS:
                v.add(Level.SUSPICIOUS, "disguised_archive", f"'{base}' is really a {kind} archive", name)
            else:
                v.add(Level.SUSPICIOUS, "type_mismatch", f"'{base}' does not look like a real {ext} file (found {kind})", name)
        elif kind in LURE_KINDS and ext not in (".html", ".htm", ".url", ".pdf", ".epub"):
            v.add(Level.SUSPICIOUS, "disguised_lure", f"'{base}' is really a {LURE_KINDS[kind]}", name)
        elif kind == "iso":
            v.add(Level.SUSPICIOUS, "disk_image", f"'{base}' is a disk image", name)
        return v

    def _check_archive(self, name: str, path: str, kind: str, container: bool = False) -> Verdict:
        """container: a book format that is a zip/rar by design (EPUB, CBZ, CBR)."""
        v = Verdict()
        base = PurePosixPath(name).name
        info = archives.inspect(path, kind)
        if info.encrypted:
            v.add(Level.MALICIOUS, "password_archive", f"'{base}' is password-protected, a classic scam in media releases", name)
        blocked = EXECUTABLE_EXT - CONTAINER_ALLOWED if container else EXECUTABLE_EXT
        bad = [e for e in info.entries if extension(e) in blocked]
        if bad:
            v.add(Level.MALICIOUS, "archive_executable", f"'{base}' contains program files: {', '.join(bad[:3])}", name)
        # Programs are hidden one level further down: in an archive or disk image inside the archive.
        nested = [e for e in info.entries if (x := extension(e)) in ARCHIVE_EXT | DISK_IMAGE_EXT or is_split_rar(x)]
        if nested:
            v.add(Level.SUSPICIOUS, "archive_nested", f"'{base}' contains another archive or disk image: "
                                                      f"{', '.join(nested[:3])}", name)
        if info.error:
            v.add(Level.SUSPICIOUS, "archive_unreadable", f"could not read '{base}': {info.error}", name)
        if not container and not self.allow_archives and not v.findings:
            v.add(Level.SUSPICIOUS, "archive", f"archive '{base}' in a media release", name)
        return v

    async def _clamav(self, name: str, path: str, ext: str, kind: str, required: bool = False) -> Verdict:
        v = Verdict()
        if self.clamd is None:
            return v
        base = PurePosixPath(name).name
        media = ext in VIDEO_EXT | AUDIO_EXT and kind in filetype.MEDIA_KINDS
        if media and not self.scan_media:
            return v
        if os.path.getsize(path) > self.stream_max_bytes:
            if not media:
                v.add(Level.CLEAN, "clamav_skipped", f"'{base}' is too large to stream to ClamAV", name)
            return v
        res = await self.clamd.scan_file(path)
        if res.infected:
            v.add(Level.MALICIOUS, "clamav", f"ClamAV detected {res.signature} in '{base}'", name)
        elif "size limit" in res.error:
            v.add(Level.CLEAN, "clamav_skipped", f"'{base}' is larger than clamd's StreamMaxLength; lower "
                                                 "CLAMAV_STREAM_MAX_MB to match it", name)
        elif res.error:
            if required:
                raise ClamavUnavailable(res.error)
            # Not scanned is not clean: hold it (by default) until ClamAV is back, then it's checked again.
            v.add(Level.SUSPICIOUS, "clamav_unavailable", f"ClamAV could not scan '{base}': {res.error}", name)
        return v
