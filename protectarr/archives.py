"""List archive contents without extracting, and detect password protection."""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field


@dataclass
class ArchiveInfo:
    entries: list[str] = field(default_factory=list)
    encrypted: bool = False
    error: str = ""


def inspect(path: str, kind: str) -> ArchiveInfo:
    try:
        if kind == "zip":
            return _zip(path)
        if kind == "rar":
            return _rar(path)
        if kind == "7z":
            return _7z(path)
    except Exception as exc:  # corrupt or unsupported archives are reported, not fatal
        return ArchiveInfo(error=f"{type(exc).__name__}: {exc}")
    return ArchiveInfo(error=f"cannot list {kind} archives")


def _zip(path: str) -> ArchiveInfo:
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        return ArchiveInfo(
            entries=[i.filename for i in infos],
            encrypted=any(i.flag_bits & 0x1 for i in infos),
        )


def _rar(path: str) -> ArchiveInfo:
    import rarfile

    try:
        with rarfile.RarFile(path) as rf:
            return ArchiveInfo(entries=rf.namelist(), encrypted=rf.needs_password())
    except rarfile.PasswordRequired:
        # Encrypted headers: even the file list needs a password.
        return ArchiveInfo(encrypted=True)
    except rarfile.NeedFirstVolume:
        return ArchiveInfo(error="not the first volume of a split archive")


def _7z(path: str) -> ArchiveInfo:
    import py7zr

    try:
        with py7zr.SevenZipFile(path) as sz:
            return ArchiveInfo(entries=sz.getnames(), encrypted=sz.needs_password())
    except py7zr.exceptions.PasswordRequired:
        return ArchiveInfo(encrypted=True)
