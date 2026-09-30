"""Move rejected files out of the download folder into a locked-down quarantine."""

from __future__ import annotations

import json
import os
import shutil
import stat
import time
from pathlib import Path


class Quarantine:
    def __init__(self, root: str):
        self.root = Path(root)

    def store(self, torrent_hash: str, name: str, files: list[tuple[str, str]], record: dict) -> str:
        """Move (relative name, local path) files into a new quarantine folder. Returns its id."""
        qid = f"{time.strftime('%Y%m%d-%H%M%S')}-{torrent_hash[:8]}"
        base = self.root / qid
        moved = []
        for rel, src in files:
            if not os.path.isfile(src):
                continue
            dest = base / "files" / _safe_rel(rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(src, dest)
            os.chmod(dest, stat.S_IRUSR)  # read-only, never executable
            moved.append({"name": rel, "original_path": src, "stored_as": str(dest.relative_to(base))})
        base.mkdir(parents=True, exist_ok=True)
        (base / "record.json").write_text(json.dumps(
            {**record, "id": qid, "hash": torrent_hash, "name": name, "files": moved,
             "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, indent=2))
        return qid

    def record(self, qid: str) -> dict:
        return json.loads((self._dir(qid) / "record.json").read_text())

    def restore(self, qid: str) -> list[str]:
        """Put files back where they came from. Returns the restored paths."""
        base = self._dir(qid)
        restored = []
        for f in self.record(qid)["files"]:
            src = base / f["stored_as"]
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
        for p in base.rglob("*"):
            if p.is_file():
                os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        shutil.rmtree(base)

    def _dir(self, qid: str) -> Path:
        if "/" in qid or qid.startswith("."):
            raise ValueError("bad quarantine id")
        d = self.root / qid
        if not (d / "record.json").exists():
            raise FileNotFoundError(qid)
        return d


def _safe_rel(rel: str) -> Path:
    parts = [p for p in Path(rel).parts if p not in ("..", ".", "/", "")]
    return Path(*parts) if parts else Path("file")
