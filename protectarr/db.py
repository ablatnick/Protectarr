"""SQLite store for torrent state, decisions and quarantine entries."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS torrents (
    hash TEXT PRIMARY KEY,
    name TEXT,
    category TEXT,
    metadata_level TEXT,
    content_level TEXT,
    blocked INTEGER DEFAULT 0,
    updated REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    hash TEXT,
    name TEXT,
    stage TEXT,
    level TEXT,
    summary TEXT,
    action TEXT,
    findings TEXT
);
CREATE TABLE IF NOT EXISTS blocklist (
    hash TEXT PRIMARY KEY,
    name TEXT,
    reason TEXT,
    ts REAL
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT,
    name TEXT,
    category TEXT,
    stage TEXT,
    level TEXT,
    summary TEXT,
    findings TEXT,
    quarantine_id TEXT,
    ts REAL,
    status TEXT DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    hash TEXT,
    name TEXT,
    level TEXT,
    summary TEXT,
    ts REAL,
    status TEXT DEFAULT 'held'
);
"""

# Columns added after the first release; created on start-up when missing.
MIGRATIONS = [("events", "indexer", "TEXT DEFAULT ''"), ("decisions", "indexer", "TEXT DEFAULT ''")]


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.executescript(SCHEMA)
            for table, column, decl in MIGRATIONS:
                cols = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
                if column not in cols:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            self.conn.commit()

    def _exec(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur.fetchall()

    def torrent(self, h: str) -> sqlite3.Row | None:
        rows = self._exec("SELECT * FROM torrents WHERE hash=?", (h,))
        return rows[0] if rows else None

    def set_stage(self, h: str, name: str, category: str, stage: str, level: str, blocked: bool = False) -> None:
        col = "metadata_level" if stage == "metadata" else "content_level"
        self._exec(
            f"INSERT INTO torrents(hash,name,category,{col},blocked,updated) VALUES(?,?,?,?,?,?) "
            f"ON CONFLICT(hash) DO UPDATE SET {col}=excluded.{col}, blocked=MAX(blocked, excluded.blocked), "
            f"name=excluded.name, updated=excluded.updated",
            (h, name, category, level, int(blocked), time.time()))

    def log(self, h: str, name: str, stage: str, level: str, summary: str, action: str, findings: list[dict],
            indexer: str = "") -> None:
        self._exec("INSERT INTO events(ts,hash,name,stage,level,summary,action,findings,indexer) "
                   "VALUES(?,?,?,?,?,?,?,?,?)",
                   (time.time(), h, name, stage, level, summary, action, json.dumps(findings), indexer or ""))

    def indexer_stats(self) -> list[dict]:
        """Releases blocked or denied per indexer, worst first."""
        rows = self._exec(
            "SELECT indexer, COUNT(DISTINCT hash) AS bad, MAX(ts) AS last FROM events "
            "WHERE indexer != '' AND (action LIKE 'blocked%' OR action LIKE 'denied%') "
            "GROUP BY indexer ORDER BY bad DESC, last DESC")
        return [dict(r) for r in rows]

    def get_setting(self, key: str, default=None):
        rows = self._exec("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set_setting(self, key: str, value) -> None:
        self._exec("INSERT OR REPLACE INTO settings VALUES(?,?)", (key, json.dumps(value)))

    def events(self, limit: int = 100) -> list[dict]:
        rows = self._exec("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [{**dict(r), "findings": json.loads(r["findings"] or "[]")} for r in rows]

    def block_hash(self, h: str, name: str, reason: str) -> None:
        self._exec("INSERT OR REPLACE INTO blocklist VALUES(?,?,?,?)", (h.lower(), name, reason, time.time()))

    def unblock_hash(self, h: str) -> None:
        self._exec("DELETE FROM blocklist WHERE hash=?", (h.lower(),))

    def is_blocked(self, h: str) -> bool:
        return bool(self._exec("SELECT 1 FROM blocklist WHERE hash=?", (h.lower(),)))

    def add_quarantine(self, qid: str, h: str, name: str, level: str, summary: str) -> None:
        self._exec("INSERT INTO quarantine(id,hash,name,level,summary,ts) VALUES(?,?,?,?,?,?)",
                   (qid, h, name, level, summary, time.time()))

    def quarantine_items(self, status: str = "held") -> list[dict]:
        return [dict(r) for r in self._exec("SELECT * FROM quarantine WHERE status=? ORDER BY ts DESC", (status,))]

    def quarantine_item(self, qid: str) -> dict | None:
        rows = self._exec("SELECT * FROM quarantine WHERE id=?", (qid,))
        return dict(rows[0]) if rows else None

    def set_quarantine_status(self, qid: str, status: str) -> None:
        self._exec("UPDATE quarantine SET status=? WHERE id=?", (status, qid))

    def has_any_torrent(self) -> bool:
        return bool(self._exec("SELECT 1 FROM torrents LIMIT 1"))

    def add_decision(self, h: str, name: str, category: str, stage: str, level: str, summary: str,
                     findings: list[dict], quarantine_id: str | None, indexer: str = "") -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO decisions(hash,name,category,stage,level,summary,findings,quarantine_id,ts,indexer) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (h, name, category, stage, level, summary, json.dumps(findings), quarantine_id, time.time(),
                 indexer or ""))
            self.conn.commit()
            return cur.lastrowid

    def pending_decisions(self) -> list[dict]:
        rows = self._exec("SELECT * FROM decisions WHERE status='pending' ORDER BY ts DESC")
        return [{**dict(r), "findings": json.loads(r["findings"] or "[]")} for r in rows]

    def decision(self, did: int) -> dict | None:
        rows = self._exec("SELECT * FROM decisions WHERE id=?", (did,))
        return {**dict(rows[0]), "findings": json.loads(rows[0]["findings"] or "[]")} if rows else None

    def resolve_decision(self, did: int, status: str) -> None:
        self._exec("UPDATE decisions SET status=? WHERE id=?", (status, did))
