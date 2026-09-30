"""Move rejected files out of the download folder into a locked-down quarantine."""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import time
from pathlib import Path

log = logging.getLogger(__name__)
# Added to a file that couldn't be moved into quarantine: no *arr app imports a file with this extension.
HELD_SUFFIX = ".protectarr-held"


class Quarantine:
    def __init__(self, root: str, fallback_root: str | None = None):
        self.root = Path(root)
        # Where the record goes when the quarantine folder itself can't be written (full disk, wrong owner).
        self.fallback_root = Path(fallback_root) if fallback_root else None

    def store(self, torrent_hash: str, name: str, files: list[tuple[str, str]], record: dict) -> str:
        """Move (relative name, local path) files into a new quarantine folder. Returns its id.

        When they can't be moved there, each file is renamed where it is (with HELD_SUFFIX) instead, so no
        *arr app imports it. Raises OSError only when neither works."""
        qid = f"{time.strftime('%Y%m%d-%H%M%S')}-{torrent_hash[:8]}"
        base = self.root / qid
        present = [(rel, src) for rel, src in files if os.path.isfile(src)]
        try:
            moved = self._move_all(base, present)
            base.mkdir(parents=True, exist_ok=True)
            self._write_record(base, record, qid, torrent_hash, name, moved)
            return qid
        except OSError as exc:
            log.warning("could not move files into quarantine (%s); locking them in place instead", exc)
            shutil.rmtree(base, ignore_errors=True)
        moved = self._hide_in_place(present)
        for root in (self.root, self.fallback_root):
            if root is None:
                continue
            try:
                (root / qid).mkdir(parents=True, exist_ok=True)
                self._write_record(root / qid, record, qid, torrent_hash, name, moved)
                return qid
            except OSError:
                shutil.rmtree(root / qid, ignore_errors=True)
        self._undo_in_place(moved)
        raise OSError(f"could not quarantine or record '{name}'")

    def _move_all(self, base: Path, files: list[tuple[str, str]]) -> list[dict]:
        moved: list[dict] = []
        try:
            for rel, src in files:
                dest = base / "files" / _safe_rel(rel)
                while dest.exists():  # two names that clean up to the same path
                    dest = dest.with_name("_" + dest.name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.move(src, dest)
                except OSError:
                    dest.unlink(missing_ok=True)  # half-copied across filesystems
                    raise
                os.chmod(dest, stat.S_IRUSR)  # read-only, never executable
                moved.append({"name": rel, "original_path": src, "stored_as": str(dest.relative_to(base))})
        except OSError:
            for m in reversed(moved):  # put back what already moved, so nothing is left half-quarantined
                try:
                    p = base / m["stored_as"]
                    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
                    shutil.move(p, m["original_path"])
                except OSError as exc:
                    log.error("could not put %s back: %s", m["original_path"], exc)
            raise
        return moved

    def _hide_in_place(self, files: list[tuple[str, str]]) -> list[dict]:
        moved = []
        try:
            for rel, src in files:
                dest = src + HELD_SUFFIX
                os.rename(src, dest)
                os.chmod(dest, stat.S_IRUSR)
                moved.append({"name": rel, "original_path": src, "stored_as": dest, "in_place": True})
        except OSError:
            self._undo_in_place(moved)
            raise
        return moved

    @staticmethod
    def _undo_in_place(moved: list[dict]) -> None:
        for m in moved:
            try:
                os.chmod(m["stored_as"], stat.S_IRUSR | stat.S_IWUSR)
                os.rename(m["stored_as"], m["original_path"])
            except OSError as exc:
                log.error("could not put %s back: %s", m["original_path"], exc)

    @staticmethod
    def _write_record(base: Path, record: dict, qid: str, torrent_hash: str, name: str, moved: list[dict]) -> None:
        (base / "record.json").write_text(json.dumps(
            {**record, "id": qid, "hash": torrent_hash, "name": name, "files": moved,
             "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, indent=2))

    def record(self, qid: str) -> dict:
        return json.loads((self._dir(qid) / "record.json").read_text())

    def stored_files(self, qid: str) -> list[tuple[str, str]]:
        """(relative name, where it is now) of each quarantined file, for scanning it again."""
        base = self._dir(qid)
        return [(f["name"], str(base / f["stored_as"])) for f in self.record(qid)["files"]]

    def restore(self, qid: str) -> list[str]:
        """Put files back where they came from. Returns the restored paths."""
        base = self._dir(qid)
        restored = []
        for f in self.record(qid)["files"]:
            src = base / f["stored_as"]  # an absolute stored_as (locked in place) stays absolute
            if not src.exists():
                continue
            os.chmod(src, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
            dest = Path(f["original_path"])
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(src, dest)
            restored.append(str(dest))
        shutil.rmtree(base)
        return restored

    def delete(self, qid: str) -> None:
        base = self._dir(qid)
        for f in self.record(qid)["files"]:
            if f.get("in_place"):
                p = Path(f["stored_as"])
                if p.exists():
                    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
                    p.unlink()
        for p in base.rglob("*"):
            if p.is_file():
                os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        shutil.rmtree(base)

    def _dir(self, qid: str) -> Path:
        if "/" in qid or qid.startswith("."):
            raise ValueError("bad quarantine id")
        for root in (self.root, self.fallback_root):
            if root is not None and (root / qid / "record.json").exists():
                return root / qid
        raise FileNotFoundError(qid)


def _safe_rel(rel: str) -> Path:
    parts = [p for p in Path(rel).parts if p not in ("..", ".", "/", "")]
    return Path(*parts) if parts else Path("file")
