"""Completion-stage scan: real file types, archive contents and ClamAV."""

from __future__ import annotations

import asyncio
import os
from pathlib import PurePosixPath

from . import archives, filetype
from .clamav import ClamdClient
from .findings import Level, Verdict
from .rules import AUDIO_EXT, EXECUTABLE_EXT, VIDEO_EXT, extension

LURE_KINDS = {"html": "web page", "url_shortcut": "internet shortcut", "pdf": "PDF document"}
# EPUB 3 books may legitimately carry JavaScript.
CONTAINER_ALLOWED = {".js"}


class Scanner:
    def __init__(self, clamd: ClamdClient | None, stream_max_bytes: int, allow_archives: bool = False):
        self.clamd = clamd
        self.stream_max_bytes = stream_max_bytes
        self.allow_archives = allow_archives

    async def scan(self, files: list[tuple[str, str]], profile: str = "tv") -> Verdict:
        """files: (display name relative to the torrent, local path) pairs of downloaded files."""
        v = Verdict()
        for name, path in files:
            if not os.path.isfile(path):
                v.add(Level.CLEAN, "missing", f"'{name}' not found on disk, skipped", name)
                continue
            v.extend(await self.scan_file(name, path, profile))
        return v

    async def sniff_partial(self, name: str, path: str) -> Verdict:
        """Check a file that is still downloading, from its first piece only: is it really what its name says?"""
        kind = await asyncio.to_thread(filetype.sniff, path)
        return self._type_findings(name, extension(name), kind)

    async def scan_file(self, name: str, path: str, profile: str = "tv") -> Verdict:
        ext = extension(name)
        kind = await asyncio.to_thread(filetype.sniff, path)
        v = self._type_findings(name, ext, kind)

        if kind in ("zip", "rar", "7z"):
            container = profile == "book" and ext in filetype.CONTAINER_EXT
            v.extend(await asyncio.to_thread(self._check_archive, name, path, kind, container))

        # A file already known to be malicious needs no second opinion, and ClamAV can take a while.
        if v.level < Level.MALICIOUS:
            v.extend(await self._clamav(name, path, ext, kind))
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
        if info.error:
            v.add(Level.SUSPICIOUS, "archive_unreadable", f"could not read '{base}': {info.error}", name)
        if not container and not self.allow_archives and not v.findings:
            v.add(Level.SUSPICIOUS, "archive", f"archive '{base}' in a media release", name)
        return v

    async def _clamav(self, name: str, path: str, ext: str, kind: str) -> Verdict:
        v = Verdict()
        if self.clamd is None:
            return v
        size = os.path.getsize(path)
        if size > self.stream_max_bytes:
            if not (ext in VIDEO_EXT | AUDIO_EXT and kind in filetype.MEDIA_KINDS):
                v.add(Level.CLEAN, "clamav_skipped", f"'{PurePosixPath(name).name}' is too large to stream to ClamAV", name)
            return v
        res = await self.clamd.scan_file(path)
        if res.infected:
            v.add(Level.MALICIOUS, "clamav", f"ClamAV detected {res.signature} in '{PurePosixPath(name).name}'", name)
        elif res.error:
            v.add(Level.CLEAN, "clamav_error", f"ClamAV could not scan '{PurePosixPath(name).name}': {res.error}", name)
        return v
