#!/usr/bin/env python3
"""Fill the e2e stack's Protectarr with made-up activity for screenshots (README, docs).

    python3 e2e/run.py          # start the stack and leave it running
    python3 e2e/demo.py         # replace its activity, review and quarantine with demo data

Every release, group and indexer name here is invented. Only the standard library is used.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from protectarr.db import Store  # noqa: E402

DB = HERE / "work" / "protectarr" / "protectarr.db"
QUARANTINE = HERE / "work" / "quarantine"
NOW = time.time()
H, M = 3600, 60


def f(level, code, message, path=""):
    return {"level": level, "code": code, "message": message, "path": path}


# (age in seconds, hash, name, stage, level, summary, action, findings, indexer)
EVENTS = [
    (2 * M, "a1", "The.Hollow.Crown.2024.1080p.WEB-DL.DDP5.1.H.264-NOVA", "metadata", "malicious",
     "'The.Hollow.Crown.2024.1080p.mkv.exe' pretends to be a video but is a .exe program",
     "blocked: removed and blocklisted in Radarr",
     [f("malicious", "double_extension", "'The.Hollow.Crown.2024.1080p.mkv.exe' pretends to be a video but is "
       "a .exe program", "The.Hollow.Crown.2024.1080p.mkv.exe")], "TorrentHaven (Prowlarr)"),
    (9 * M, "a2", "Riverside.S03E07.1080p.WEB.H264-KITE", "content", "clean", "clean", "allow", [], ""),
    (10 * M, "a2", "Riverside.S03E07.1080p.WEB.H264-KITE", "metadata", "clean", "clean", "allow", [], ""),
    (24 * M, "a3", "Northern.Lights.S01E02.2160p.WEB.H265-ORBIT", "early", "malicious",
     "'Northern.Lights.S01E02.2160p.mkv' is really a program (pe) disguised as .mkv",
     "blocked: quarantined, removed and blocklisted in Sonarr",
     [f("malicious", "hidden_executable", "'Northern.Lights.S01E02.2160p.mkv' is really a program (pe) disguised "
       "as .mkv", "Northern.Lights.S01E02.2160p.mkv")], "OpenIndex (Prowlarr)"),
    (41 * M, "a4", "Quiet.Harbor.S02E01.720p.HDTV.x264-DUSK", "metadata", "suspicious",
     "largest video is 2.0 MB, below the 30 MB minimum", "held for your decision",
     [f("suspicious", "too_small", "largest video is 2.0 MB, below the 30 MB minimum", "Quiet.Harbor.S02E01.mkv")],
     "TorrentHaven (Prowlarr)"),
    (1 * H + 5 * M, "a5", "Paper Lanterns - Low Tide (2021) [FLAC 24-96]", "content", "clean", "clean", "allow", [], ""),
    (1 * H + 6 * M, "a5", "Paper Lanterns - Low Tide (2021) [FLAC 24-96]", "metadata", "clean", "clean", "allow", [],
     ""),
    (2 * H + 12 * M, "a6", "Glass.Mountain.2023.1080p.BluRay.x264-PRISM", "content", "malicious",
     "'Glass.Mountain.2023.1080p.zip' is password-protected, a classic scam in media releases",
     "blocked: quarantined, removed and blocklisted in Radarr",
     [f("malicious", "password_archive", "'Glass.Mountain.2023.1080p.zip' is password-protected, a classic scam in "
       "media releases", "Glass.Mountain.2023.1080p.zip"),
      f("suspicious", "lure_name", "'Password.txt' looks like a password or codec lure", "Password.txt")],
     "OpenIndex (Prowlarr)"),
    (3 * H, "a7", "Cedar.Falls.S04E10.1080p.WEB.H264-KITE", "content", "clean", "clean", "allow", [], ""),
    (5 * H + 30 * M, "a8", "Summer.of.Static.2022.1080p.WEB.H264-VOLT", "content", "malicious",
     "ClamAV detected Eicar-Test-Signature in 'readme.txt'",
     "blocked: quarantined, Radarr had already imported it: deleted 1 imported file(s), marked the grab failed so "
     "it's blocklisted and searched again; removed from qBittorrent",
     [f("malicious", "clamav", "ClamAV detected Eicar-Test-Signature in 'readme.txt'", "readme.txt")],
     "FreshReleases (Prowlarr)"),
    (8 * H, "a9", "Harborlight.S01E03.1080p.WEB.H264-WAVE", "metadata", "suspicious",
     "'Harborlight.S01E03.wmv' is WMV/ASF, a format used by codec-download lures", "denied by you: removed and "
     "blocklisted in Sonarr",
     [f("suspicious", "legacy_video", "'Harborlight.S01E03.wmv' is WMV/ASF, a format used by codec-download lures",
        "Harborlight.S01E03.wmv")], "TorrentHaven (Prowlarr)"),
    (20 * H, "b1", "Midnight.Orchard.S02E08.1080p.WEB.H264-KITE", "content", "clean", "clean", "allow", [], ""),
    (26 * H, "b2", "Iron.Coast.2024.2160p.WEB-DL.DV.HDR.H265-NOVA", "metadata", "malicious",
     "hidden right-to-left character disguises the real extension of 'Iron.Coast.2024.2160p\u202evkm.scr'",
     "blocked: removed and blocklisted in Radarr",
     [f("malicious", "rtlo", "hidden right-to-left character disguises the real extension of "
       "'Iron.Coast.2024.2160p\u202evkm.scr'", "Iron.Coast.2024.2160p\u202evkm.scr")], "FreshReleases (Prowlarr)"),
]

# (hash, name, category, stage, level, summary, findings, indexer, files to hold)
DECISIONS = [
    ("a4", "Quiet.Harbor.S02E01.720p.HDTV.x264-DUSK", "tv-sonarr", "metadata", "suspicious",
     "largest video is 2.0 MB, below the 30 MB minimum", EVENTS[4][7], "TorrentHaven (Prowlarr)", []),
    ("c1", "Lantern.Street.S01E05.1080p.WEB.H264-FERN", "tv-sonarr", "content", "suspicious",
     "'Lantern.Street.S01E05.mkv' does not look like a real .mkv file (found unknown)",
     [f("suspicious", "type_mismatch", "'Lantern.Street.S01E05.mkv' does not look like a real .mkv file (found "
        "unknown)", "Lantern.Street.S01E05/Lantern.Street.S01E05.mkv")], "OpenIndex (Prowlarr)",
     ["Lantern.Street.S01E05/Lantern.Street.S01E05.mkv", "Lantern.Street.S01E05/Lantern.Street.S01E05.nfo"]),
]

# Blocked downloads whose files sit in quarantine: (event index, files)
QUARANTINED = [
    (3, ["Northern.Lights.S01E02.2160p.WEB.H265-ORBIT/Northern.Lights.S01E02.2160p.mkv"]),
    (7, ["Glass.Mountain.2023.1080p.BluRay.x264-PRISM/Glass.Mountain.2023.1080p.zip",
         "Glass.Mountain.2023.1080p.BluRay.x264-PRISM/Password.txt"]),
    (9, ["Summer.of.Static.2022.1080p.WEB.H264-VOLT/Summer.of.Static.2022.1080p.mkv",
         "Summer.of.Static.2022.1080p.WEB.H264-VOLT/readme.txt"]),
]


def clear_quarantine() -> None:
    if not QUARANTINE.exists():
        return
    for p in QUARANTINE.rglob("*"):
        try:
            os.chmod(p, stat.S_IRWXU if p.is_dir() else stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    for child in QUARANTINE.iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()


def quarantine(qid: str, h: str, name: str, stage: str, level: str, summary: str, findings: list, files: list,
               ts: float) -> None:
    base = QUARANTINE / qid
    stored = []
    for rel in files:
        dest = base / "files" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"demo placeholder\n")
        os.chmod(dest, stat.S_IRUSR)
        stored.append({"name": rel.split("/", 1)[-1], "original_path": f"/downloads/complete/{rel}",
                       "stored_as": f"files/{rel}"})
    (base / "record.json").write_text(json.dumps({
        "stage": stage, "level": level, "summary": summary, "findings": findings, "category": "", "id": qid,
        "hash": h, "name": name, "files": stored,
        "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))}, indent=2))


def main() -> None:
    if not DB.exists():
        sys.exit(f"{DB} not found: start the stack first with python3 e2e/run.py")
    store = Store(str(DB))
    for table in ("events", "decisions", "quarantine"):
        store._exec(f"DELETE FROM {table}")
    clear_quarantine()

    for age, h, name, stage, level, summary, action, findings, indexer in reversed(EVENTS):
        store.log(h * 20, name, stage, level, summary, action, findings, indexer)
        store._exec("UPDATE events SET ts=? WHERE id=(SELECT MAX(id) FROM events)", (NOW - age,))

    for idx, files in QUARANTINED:
        age, h, name, stage, level, summary, _, findings, _ = EVENTS[idx]
        qid = time.strftime("%Y%m%d-%H%M%S", time.localtime(NOW - age)) + f"-{(h * 4)[:8]}"
        quarantine(qid, h * 20, name, stage, level, summary, findings, files, NOW - age)
        store.add_quarantine(qid, h * 20, name, level, summary)
        store._exec("UPDATE quarantine SET ts=? WHERE id=?", (NOW - age, qid))

    for age, (h, name, cat, stage, level, summary, findings, indexer, files) in zip((41 * M, 14 * M), DECISIONS):
        qid = None
        if files:
            qid = time.strftime("%Y%m%d-%H%M%S", time.localtime(NOW - age)) + f"-{(h * 4)[:8]}"
            quarantine(qid, h * 20, name, stage, level, summary, findings, files, NOW - age)
            store.add_quarantine(qid, h * 20, name, level, summary)
        did = store.add_decision(h * 20, name, cat, stage, level, summary, findings, qid, indexer)
        store._exec("UPDATE decisions SET ts=? WHERE id=?", (NOW - age, did))
    print(f"demo data written: {len(EVENTS)} events, {len(DECISIONS)} to review, "
          f"{len(QUARANTINED)} in quarantine. Open http://127.0.0.1:19797 (any username, password e2e-ui-key)")


if __name__ == "__main__":
    main()
