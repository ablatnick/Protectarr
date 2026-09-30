"""The pipeline: watch qBittorrent, run each stage once per torrent, and act on verdicts."""

from __future__ import annotations

import asyncio
import logging
import posixpath
import time

import httpx

from .arr import ArrClient, blocklist_everywhere, find_owner
from .config import Config
from .db import Store
from .findings import Level, Verdict
from .notify import Notifier
from .qbit import PAUSED_STATES, STOPPED_STATES, QbitClient, has_metadata, is_complete
from .quarantine import Quarantine
from .rules import TorrentFile, check_metadata
from .scanner import ClamavUnavailable, Scanner

log = logging.getLogger(__name__)
SUSPICIOUS_TAG = "protectarr-suspicious"
HELD_TAG = "protectarr-held"
CATEGORY_REFRESH_SECONDS = 600
RESUME_WINDOW_SECONDS = 120
EARLY_CHECK_SECONDS = 10  # how often a downloading torrent's files are looked at
MAX_CONTENT_ATTEMPTS = 3
HEARTBEAT_SECONDS = 60
RECHECK_SECONDS = 60  # how often held downloads that ClamAV couldn't scan are tried again


class Guard:
    def __init__(self, cfg: Config, store: Store, qbit: QbitClient, arrs: list[ArrClient], scanner: Scanner,
                 quarantine: Quarantine, notifier: Notifier, background_scans: bool = False, max_scans: int = 2):
        self.cfg, self.store, self.qbit, self.arrs = cfg, store, qbit, arrs
        self.scanner, self.quarantine, self.notifier = scanner, quarantine, notifier
        self._locks: dict[str, asyncio.Lock] = {}
        self._blocked_at: dict[str, float] = {}
        # Torrents that passed the file-list check and should be started if qBittorrent stops them (wall-clock
        # deadlines, kept across restarts). A window that was still open when Protectarr stopped is reopened.
        now = time.time()
        # When Protectarr was last known to be running: torrents added since then were added while it was down.
        self._down_since: float | None = store.get_setting("alive_at")
        self._resume_until: dict[str, float] = {
            h: max(until, now + RESUME_WINDOW_SECONDS)
            for h, until in (store.get_setting("resume_until", {}) or {}).items()
            if until > now or (self._down_since and until > self._down_since)}
        self._first_poll_done = False
        self._alive_at = float("-inf")
        self._recheck_at = float("-inf")
        self._restopped: set[str] = set()
        self._others_seen: set[str] = set()
        self._content_failures: dict[str, int] = {}
        # Per downloading torrent: files fully scanned / type-checked so far, and when it was last looked at.
        self._early: dict[str, dict] = {}
        # Content scans can take a while (ClamAV); in the service they run beside the poll loop.
        self.background_scans = background_scans
        self._scan_slots = asyncio.Semaphore(max_scans)
        self._scanning: set[str] = set()
        self._tasks: set[asyncio.Task] = set()
        # category -> {"profile": ..., "source": ...}; learned from the *arr apps and kept across restarts.
        self.discovered: dict[str, dict] = store.get_setting("discovered_categories", {}) or {}
        self.arr_errors: dict[str, str] = {}
        self._categories_at = float("-inf")

    async def reconnect(self) -> None:
        """Rebuild every service client from self.cfg after the connections were changed in the web UI."""
        from .clamav import ClamdClient  # local import: guard stays importable without the web layer

        old = [self.qbit, *self.arrs]
        c = self.cfg
        self.qbit = QbitClient(c.qbittorrent.url, c.qbittorrent.username, c.qbittorrent.password)
        self.arrs = [ArrClient(a) for a in c.arr]
        self.scanner.clamd = (ClamdClient(c.clamav.host, c.clamav.port, c.clamav.timeout)
                              if c.clamav.enabled and c.clamav.host else None)
        self.scanner.stream_max_bytes = c.clamav.stream_max_mb * 1024 * 1024
        names = {a.name for a in c.arr}
        self.discovered = {k: v for k, v in self.discovered.items() if v.get("source") in names}
        self.arr_errors = {}
        self._categories_at = float("-inf")
        for client in old:
            try:
                await client.close()
            except Exception:
                pass
        if self.arrs:
            await self.refresh_categories()
        else:
            self.store.set_setting("discovered_categories", self.discovered)
        try:
            await self.adopt_existing()  # first successful connection: leave finished torrents alone
        except Exception as exc:
            log.info("qBittorrent not reachable yet: %s", exc)

    # ----- categories -------------------------------------------------------------------------------------

    async def refresh_categories(self) -> None:
        """Ask each *arr app which qBittorrent category it uses, so nothing needs configuring by hand."""
        found: dict[str, dict] = {}
        for c in self.arrs:
            try:
                cats = c.cfg.categories or await c.qbit_categories()
                self.arr_errors.pop(c.name, None)
            except Exception as exc:  # unreachable, wrong key, or not an *arr app at all
                self.arr_errors[c.name] = _http_error(exc) if isinstance(exc, httpx.HTTPError) else _odd_answer(exc)
                # Keep what we learned from this app last time.
                cats = [k for k, v in self.discovered.items() if v.get("source") == c.name]
            for cat in cats:
                found.setdefault(cat, {"profile": c.cfg.profile, "source": c.name})
        if found != self.discovered:
            log.info("categories: %s", ", ".join(f"{k} ({v['source']}, {v['profile']})" for k, v in found.items())
                     or "none found")
            self.discovered = found
            self.store.set_setting("discovered_categories", found)
        self._categories_at = time.monotonic()

    def watched(self, category: str) -> bool:
        explicit = self.cfg.qbittorrent.categories
        if explicit:
            return category in explicit
        # Nothing is checked until an *arr app (or an explicit category) says which torrents are media.
        return category in self.discovered

    def profile(self, category: str) -> str:
        if category in self.cfg.rules.category_profiles:
            return self.cfg.rules.category_profiles[category]
        return self.discovered.get(category, {}).get("profile", "tv")

    def category_table(self) -> list[dict]:
        cats = set(self.cfg.qbittorrent.categories) | set(self.discovered) | set(self.cfg.rules.category_profiles)
        rows = []
        for cat in sorted(cats):
            source = ("config" if cat in self.cfg.qbittorrent.categories
                      else self.discovered.get(cat, {}).get("source", "config"))
            rows.append({"category": cat, "profile": self.profile(cat), "source": source, "watched": self.watched(cat)})
        return rows

    # ----- polling -----------------------------------------------------------------------------------------

    async def adopt_existing(self) -> int:
        """On first run, leave torrents that already finished alone instead of scanning the whole client."""
        if self.store.has_any_torrent() or not self.qbit.configured:
            return 0
        count = 0
        for t in await self.qbit.torrents():
            if is_complete(t):
                self.store.set_stage(t["hash"], t["name"], t.get("category", ""), "metadata", "preexisting")
                self.store.set_stage(t["hash"], t["name"], t.get("category", ""), "content", "preexisting")
                count += 1
        return count

    async def run_forever(self) -> None:
        while True:
            try:
                if self.arrs and time.monotonic() - self._categories_at > CATEGORY_REFRESH_SECONDS:
                    await self.refresh_categories()
                await self.poll()
                if time.monotonic() - self._alive_at > HEARTBEAT_SECONDS:
                    self._alive_at = time.monotonic()
                    self.store.set_setting("alive_at", time.time())
                if time.monotonic() - self._recheck_at > RECHECK_SECONDS:
                    self._recheck_at = time.monotonic()
                    await self.recheck_unscanned()
            except Exception:
                log.exception("poll failed")
            await asyncio.sleep(self.cfg.poll_seconds)

    async def poll(self) -> None:
        if not self.qbit.configured:
            return
        for t in await self.qbit.torrents():
            try:
                await self.process(t)
            except Exception:
                log.exception("checking '%s' failed", t.get("name"))
        self._first_poll_done = True

    async def process_hash(self, torrent_hash: str) -> None:
        t = await self.qbit.torrent(torrent_hash)
        if t:
            await self.process(t)

    async def process(self, t: dict) -> None:
        h = t["hash"]
        if not self.watched(t.get("category", "")):
            row = self.store.torrent(h)
            if row is None:
                await self._release_other(t)
                return
            # Checked before under a watched category and since moved out of it, e.g. by the *arr app's
            # "category after import": finish checking it as what it was.
            t = {**t, "category": row["category"]}
        if h in self._scanning:
            # A scan holds its lock; don't wait for it, but still start it if qBittorrent's stop condition hit.
            await self._resume_if_stopped(t)
            return
        lock = self._locks.setdefault(h, asyncio.Lock())
        async with lock:
            if self.store.is_blocked(h):
                # Either we just removed it and qBittorrent hasn't caught up, or it was added again.
                if time.monotonic() - self._blocked_at.get(h, -1e9) > 120:
                    await self._block(t, "metadata", Verdict(), "release was blocked before", quarantine_files=False,
                                      history=False)
                return
            row = self.store.torrent(h)
            if not has_metadata(t):
                return
            if row is None or row["metadata_level"] is None:
                if not await self.metadata_stage(t, fresh=row is None):
                    return
                row = self.store.torrent(h)
            if "held" in (row["metadata_level"], row["content_level"]):
                await self._keep_held(t)  # waiting for the user to allow or deny it
                return
            await self._resume_if_stopped(t)
            if row["content_level"] is not None:
                return
            if not is_complete(t):
                if self.cfg.early_checks and self._early_due(t):
                    if not self.background_scans:
                        await self.early_stage(t)
                        return
                    self._scanning.add(h)
                    self._spawn(self._in_background(t, self.early_stage, content=False))
                return
            if not self.background_scans:
                try:
                    await self.content_stage(t)
                except Exception as exc:
                    log.exception("content check of '%s' failed", t.get("name"))
                    await self._content_failed(t, exc)
                return
            self._scanning.add(h)
        # Scans (ClamAV, big archives) run beside the poll loop, so they never delay checking new torrents.
        self._spawn(self._in_background(t, self.content_stage, content=True))

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _in_background(self, t: dict, stage, content: bool) -> None:
        h = t["hash"]
        try:
            async with self._scan_slots, self._locks.setdefault(h, asyncio.Lock()):
                await stage(t)
        except Exception as exc:
            log.exception("%s check of '%s' failed", "content" if content else "early", t.get("name"))
            if content:
                async with self._locks.setdefault(h, asyncio.Lock()):
                    await self._content_failed(t, exc)
        finally:
            self._scanning.discard(h)

    async def _keep_held(self, t: dict) -> None:
        """A held torrent stays stopped until you decide, even if something (you, qbit_manage) starts it."""
        h = t["hash"]
        if not has_metadata(t) or t.get("state") in PAUSED_STATES | {"error", "missingFiles"}:
            return
        await self.qbit.stop(h)
        if h not in self._restopped:
            self._restopped.add(h)
            self.store.log(h, t["name"], "review", "suspicious", "was started while waiting for your decision",
                           "stopped again: use Allow on the Review page to let it download", [])

    async def _content_failed(self, t: dict, exc: Exception) -> None:
        """Retry a few polls later (a file may still be moving). After that, a download that can't be checked is
        treated as suspicious (held for you by default), never passed as if it were clean."""
        h = t["hash"]
        self._content_failures[h] = self._content_failures.get(h, 0) + 1
        if self._content_failures[h] < MAX_CONTENT_ATTEMPTS:
            return
        v = Verdict()
        v.add(Level.SUSPICIOUS, "not_checked",
              f"could not check the downloaded files: {exc.__class__.__name__}: {exc}")
        try:  # the caller holds the torrent's lock
            row = self.store.torrent(h)
            if row is not None and row["content_level"] is not None:
                return
            files = self._local_files(t, await self.qbit.files(h))
            await self._apply(t, "content", v, files)
            self._content_failures.pop(h, None)
        except Exception:
            log.exception("could not hold '%s' after its check failed; trying again", t.get("name"))

    async def drain(self) -> None:
        """Wait for background scans (used by tests and shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    # ----- stages ------------------------------------------------------------------------------------------

    async def metadata_stage(self, t: dict, fresh: bool) -> bool:
        """Returns False when the torrent was blocked or held."""
        h, name, cat = t["hash"], t["name"], t.get("category", "")
        profile = self.profile(cat)
        files = await self.qbit.files(h)
        verdict = check_metadata(
            [TorrentFile(f["name"], f["size"]) for f in files],
            self.cfg.min_video_bytes(cat, profile), self.cfg.rules.allow_archives,
            self.cfg.rules.extra_blocked_extensions, profile)
        action = self._action(verdict)
        if action == "block":
            await self._block(t, "metadata", verdict, verdict.summary(), quarantine_files=False)
            return False
        if action == "hold":
            await self._hold(t, "metadata", verdict)
            return False
        self.store.set_stage(h, name, cat, "metadata", verdict.level.label)
        self.store.log(h, name, "metadata", verdict.level.label, verdict.summary(), action, verdict.to_list())
        if action == "alert":
            await self.qbit.add_tags(h, SUSPICIOUS_TAG)
            await self.notifier.send("Protectarr: suspicious download", f"{name}\n{verdict.summary()}")
        if fresh and self.cfg.qbittorrent.resume_after_metadata_check and t.get("progress", 0) < 1:
            # qBittorrent's "stop when metadata received" holds new torrents for us. For torrents added from
            # a .torrent file it can stop them a moment after we've already looked, so keep watching briefly.
            self._resume_later(h)
            await self._resume_if_stopped(t)
        return True

    async def _release_other(self, t: dict) -> None:
        """Start a new torrent in a category Protectarr doesn't check, if qBittorrent's "stop after metadata"
        condition stopped it. Only torrents added in the last couple of minutes, and only once each."""
        h = t["hash"]
        if not has_metadata(t):
            return
        if h not in self._others_seen:
            self._others_seen.add(h)
            q = self.cfg.qbittorrent
            added = t.get("added_on", 0)
            fresh = time.time() - added < RESUME_WINDOW_SECONDS or (
                # added while Protectarr was down, so qBittorrent's stop condition held it with nobody to release it
                not self._first_poll_done and self._down_since is not None and added >= self._down_since - 5)
            if q.resume_after_metadata_check and q.resume_other_categories and fresh and t.get("progress", 0) < 1:
                self._resume_later(h)
        await self._resume_if_stopped(t)

    def _resume_later(self, h: str) -> None:
        self._resume_until[h] = time.time() + RESUME_WINDOW_SECONDS
        self._save_resume()

    def _save_resume(self) -> None:
        now = time.time()
        self._resume_until = {k: v for k, v in self._resume_until.items() if v > now}
        self.store.set_setting("resume_until", self._resume_until)

    async def _resume_if_stopped(self, t: dict) -> None:
        h = t["hash"]
        until = self._resume_until.get(h)
        if until is None:
            return
        if time.time() > until or t.get("progress", 0) >= 1:
            self._resume_until.pop(h, None)
            self._save_resume()
        elif t.get("state") in STOPPED_STATES and HELD_TAG not in (t.get("tags") or ""):
            self._resume_until.pop(h, None)
            self._save_resume()
            await self.qbit.start(h)

    def _early_due(self, t: dict) -> bool:
        """Early checks look at a downloading torrent every EARLY_CHECK_SECONDS, not every poll."""
        st = self._early.setdefault(t["hash"], {"full": set(), "sniffed": set(), "asked_flp": False,
                                                "at": float("-inf")})
        if time.monotonic() - st["at"] < EARLY_CHECK_SECONDS or t.get("state") in STOPPED_STATES:
            return False
        st["at"] = time.monotonic()
        return True

    async def early_stage(self, t: dict) -> None:
        """Look at a torrent's files while it downloads (see Config.early_checks)."""
        h = t["hash"]
        st = self._early.setdefault(h, {"full": set(), "sniffed": set(), "asked_flp": False, "at": float("-inf")})
        if not st["asked_flp"] and not t.get("f_l_piece_prio"):
            st["asked_flp"] = True
            await self.qbit.first_last_piece_first(h)
        files = [f for f in await self.qbit.files(h) if f.get("priority", 1) != 0 and f["index"] not in st["full"]]
        waiting = [f for f in files if f.get("progress", 0) < 1 and f["index"] not in st["sniffed"]]
        pieces = await self.qbit.piece_states(h) if waiting else []
        # Unfinished files live in qBittorrent's "incomplete" folder when that's turned on.
        folders = [self.cfg.to_local(p) for p in (t.get("download_path"), t["save_path"]) if p]
        profile = self.profile(t.get("category", ""))
        verdict = Verdict()
        for f in files:
            path = _find_file(folders, f["name"])
            if not path:
                continue
            if f.get("progress", 0) >= 1:
                try:
                    verdict.extend(await self.scanner.scan_file(f["name"], path, profile, clamav_required=True))
                except ClamavUnavailable:
                    continue  # scanned again when the torrent completes
                st["full"].add(f["index"])
                st["sniffed"].add(f["index"])
            elif f["index"] not in st["sniffed"]:
                first = (f.get("piece_range") or [0])[0]
                if 0 <= first < len(pieces) and pieces[first] == 2:
                    verdict.extend(await self.scanner.sniff_partial(f["name"], path))
                    st["sniffed"].add(f["index"])
        if verdict.level == Level.CLEAN:
            return
        action = self._action(verdict)
        present = [(f["name"], p) for f in await self.qbit.files(h)
                   if (p := _find_file(folders, f["name"]))]
        if action == "block":
            await self._block(t, "early", verdict, verdict.summary(), quarantine_files=True, files=present)
        elif action == "hold":
            await self._hold(t, "early", verdict, present)
        elif not st.get("alerted"):
            st["alerted"] = True
            self.store.log(h, t["name"], "early", verdict.level.label, verdict.summary(), "alert", verdict.to_list())
            await self.qbit.add_tags(h, SUSPICIOUS_TAG)
            await self.notifier.send("Protectarr: suspicious download", f"{t['name']}\n{verdict.summary()}")

    async def content_stage(self, t: dict) -> None:
        h, cat = t["hash"], t.get("category", "")
        files = await self.qbit.files(h)
        # Files fully scanned while downloading needn't be scanned again, but if the release is blocked or held
        # every file goes to quarantine, so nothing is left for the *arr app to import.
        done = self._early.get(h, {}).get("full", set())
        local = self._local_files(t, files)
        to_scan = self._local_files(t, [f for f in files if f.get("index") not in done])
        verdict = await self.scanner.scan(to_scan, self.profile(cat))  # raises when files can't be found
        self._early.pop(h, None)
        self._content_failures.pop(h, None)
        await self._apply(t, "content", verdict, local)

    async def _apply(self, t: dict, stage: str, verdict: Verdict, files: list[tuple[str, str]]) -> None:
        """Act on a download's verdict after it finished: block, hold, or record it (and alert)."""
        h, name, cat = t["hash"], t["name"], t.get("category", "")
        action = self._action(verdict)
        if action == "block":
            await self._block(t, stage, verdict, verdict.summary(), quarantine_files=True, files=files)
            return
        if action == "hold":
            await self._hold(t, stage, verdict, files)
            return
        self.store.set_stage(h, name, cat, stage, verdict.level.label)
        self.store.log(h, name, stage, verdict.level.label, verdict.summary(), action, verdict.to_list())
        if action == "alert":
            await self.qbit.add_tags(h, SUSPICIOUS_TAG)
            await self.notifier.send("Protectarr: suspicious download", f"{name}\n{verdict.summary()}")

    def _local_files(self, t: dict, files: list[dict]) -> list[tuple[str, str]]:
        save = self.cfg.to_local(t["save_path"])
        return [(f["name"], posixpath.join(save, f["name"])) for f in files if f.get("priority", 1) != 0]

    def _action(self, verdict: Verdict) -> str:
        if verdict.level == Level.CLEAN:
            return "allow"
        return self.cfg.action_for(verdict.level.label)

    # ----- actions -----------------------------------------------------------------------------------------

    async def _block(self, t: dict, stage: str, verdict: Verdict, summary: str, quarantine_files: bool,
                     files: list[tuple[str, str]] | None = None, history: bool = True) -> None:
        h, name, cat = t["hash"], t["name"], t.get("category", "")
        level = verdict.level.label if verdict.findings else "malicious"
        await self.qbit.stop(h)
        steps = []
        if quarantine_files and files:
            try:
                qid = await asyncio.to_thread(
                    self.quarantine.store, h, name, files,
                    {"stage": stage, "level": level, "summary": summary, "findings": verdict.to_list(),
                     "category": cat})
                self.store.add_quarantine(qid, h, name, level, summary)
                steps.append("quarantined")
            except OSError as exc:
                # The files are deleted with the torrent below, which also keeps them out of the library.
                log.error("could not quarantine '%s': %s", name, exc)
                steps.append(f"could not quarantine ({exc}), so the files are deleted with the torrent")
        step, indexer = await self._remove(h, name, cat, stage, level, summary, history)
        steps.append(step)
        action = "blocked: " + ", ".join(steps)
        self.store.log(h, name, stage, level, summary, action, verdict.to_list(), indexer)
        source = f" (from {indexer})" if indexer else ""
        await self.notifier.send(f"Protectarr blocked a {level} download",
                                 f"{name}{source}\n{summary}\n{action}{self._link('/quarantine')}")

    async def _remove(self, h: str, name: str, cat: str, stage: str, level: str, reason: str,
                      history: bool = True) -> tuple[str, str]:
        """Remove the torrent (via the *arr app with blocklisting when it owns it) and remember the block.
        Returns (what was done, indexer the release came from)."""
        self._blocked_at[h] = time.monotonic()
        self._early.pop(h, None)
        # Remembered first: if removing it fails below, the next polls see a blocked torrent and try again.
        self.store.block_hash(h, name, reason)
        self.store.set_stage(h, name, cat, stage, level, blocked=True)
        removal = await blocklist_everywhere(self.arrs, h, history)
        if removal and not removal.imported:
            return removal.describe(), removal.indexer  # the app removed it from qBittorrent too
        # Not grabbed by an *arr app, or already imported (then the app no longer manages the torrent).
        try:
            await self.qbit.delete(h, delete_files=True)
            done = "removed from qBittorrent"
        except Exception as exc:
            log.error("could not remove '%s' from qBittorrent: %s", name, exc)
            done = f"COULD NOT remove it from qBittorrent yet ({exc}); trying again in 2 minutes"
        return (removal.describe() + "; " if removal else "") + done, removal.indexer if removal else ""

    async def _hold(self, t: dict, stage: str, verdict: Verdict, files: list[tuple[str, str]] | None = None) -> None:
        """Stop the torrent, lock away any downloaded files, and ask the user to allow or deny it."""
        h, name, cat = t["hash"], t["name"], t.get("category", "")
        level, summary = verdict.level.label, verdict.summary()
        await self.qbit.stop(h)
        await self.qbit.add_tags(h, HELD_TAG)
        qid = None
        if files:
            # Moving the files away also keeps the *arr app from importing them meanwhile.
            try:
                qid = await asyncio.to_thread(
                    self.quarantine.store, h, name, files,
                    {"stage": stage, "level": level, "summary": summary, "findings": verdict.to_list(),
                     "category": cat})
                self.store.add_quarantine(qid, h, name, level, summary)
            except OSError as exc:
                log.error("could not quarantine held '%s': %s", name, exc)
                summary += f". Its files could NOT be moved away ({exc}), so an *arr app may still import them"
        owner = await find_owner(self.arrs, h)
        indexer = (owner[1].get("indexer") or "") if owner else ""
        self.store.add_decision(h, name, cat, stage, level, summary, verdict.to_list(), qid, indexer)
        self.store.set_stage(h, name, cat, stage, "held")
        self.store.log(h, name, stage, level, summary, "held for your decision", verdict.to_list(), indexer)
        await self.notifier.send(
            "Protectarr is holding a suspicious download",
            f"{name}\n{summary}\nIt stays stopped until you allow or deny it.{self._link('/review')}")

    async def allow(self, decision_id: int, by: str = "allowed by you") -> None:
        d = self._pending(decision_id)
        h, name, cat, stage = d["hash"], d["name"], d["category"], d["stage"]
        async with self._locks.setdefault(h, asyncio.Lock()):
            if d["quarantine_id"]:
                await asyncio.to_thread(self.quarantine.restore, d["quarantine_id"])
                self.store.set_quarantine_status(d["quarantine_id"], "restored")
            self.store.set_stage(h, name, cat, stage, "allowed")
            self.store.resolve_decision(decision_id, "allowed")
            self.store.log(h, name, stage, d["level"], d["summary"], by, [], d.get("indexer", ""))
            self._restopped.discard(h)
            if await self.qbit.torrent(h):
                await self.qbit.remove_tags(h, HELD_TAG)
                await self.qbit.start(h)

    async def deny(self, decision_id: int, by: str = "denied by you") -> None:
        d = self._pending(decision_id)
        h, name, cat, stage = d["hash"], d["name"], d["category"], d["stage"]
        async with self._locks.setdefault(h, asyncio.Lock()):
            if d["quarantine_id"]:
                await asyncio.to_thread(self.quarantine.delete, d["quarantine_id"])
                self.store.set_quarantine_status(d["quarantine_id"], "deleted")
            step, indexer = await self._remove(h, name, cat, stage, d["level"], d["summary"])
            self.store.resolve_decision(decision_id, "denied")
            self.store.log(h, name, stage, d["level"], d["summary"], f"{by}: {step}", [],
                           indexer or d.get("indexer", ""))

    async def recheck_unscanned(self) -> None:
        """Downloads held only because ClamAV couldn't scan them are scanned again once it's back, and then
        released or blocked without waiting for you."""
        clamd = self.scanner.clamd
        waiting = [d for d in self.store.pending_decisions() if d["quarantine_id"]
                   and {f["code"] for f in d["findings"] if f["level"] != "clean"} == {"clamav_unavailable"}]
        if not waiting or clamd is None or not await clamd.ping():
            return
        for d in waiting:
            try:
                files = await asyncio.to_thread(self.quarantine.stored_files, d["quarantine_id"])
                verdict = await self.scanner.scan(files, self.profile(d["category"]), clamav_required=True)
            except ClamavUnavailable:
                return
            except Exception:
                log.exception("rechecking '%s' failed", d["name"])
                continue
            if verdict.level == Level.CLEAN:
                await self.allow(d["id"], by="released automatically: ClamAV found nothing once it was back")
            elif verdict.level == Level.MALICIOUS:
                await self.deny(d["id"], by=f"blocked automatically: {verdict.summary()}")

    def _pending(self, decision_id: int) -> dict:
        d = self.store.decision(decision_id)
        if not d or d["status"] != "pending":
            raise LookupError("no pending decision with that id")
        return d

    def _link(self, path: str) -> str:
        return f"\nReview: {self.cfg.public_url.rstrip('/')}{path}" if self.cfg.public_url else ""


def _find_file(folders: list[str], name: str) -> str | None:
    """Where a torrent file is on disk: its incomplete or its final folder, with or without ".!qB"."""
    import os
    for folder in folders:
        for candidate in (posixpath.join(folder, name), posixpath.join(folder, name) + ".!qB"):
            if os.path.isfile(candidate):
                return candidate
    return None


def _odd_answer(exc: Exception) -> str:
    return f"unexpected answer ({exc.__class__.__name__}); is this address really that app's?"


def _http_error(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return {401: "API key rejected (401)", 403: "access denied (403)"}.get(code, f"HTTP {code}")
    return f"cannot connect: {exc.__class__.__name__}"
