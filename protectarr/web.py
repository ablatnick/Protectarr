"""Web UI, hook endpoints and the background worker."""

from __future__ import annotations

import asyncio
import base64
import copy
import hmac
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import __version__
from .arr import ArrClient
from .clamav import ClamdClient
from .config import ARR_KINDS, Config, apply_connections, connections_of, merge_connections
from .db import Store
from .guard import Guard
from .login import Logins
from .qbit import QbitClient
from .quarantine import Quarantine
from .scanner import Scanner
from .status import run_checks

log = logging.getLogger(__name__)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.filters["ago"] = lambda ts: _ago(ts)


def _ago(ts: float) -> str:
    s = int(time.time() - ts)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{s // n}{unit} ago"
    return f"{s}s ago"


def build_guard(cfg: Config) -> Guard:
    store = Store(os.path.join(cfg.data_dir, "protectarr.db"))
    # Connections saved on the Settings page take precedence over the file and environment.
    apply_connections(cfg, store.get_setting("connections"))
    clamd = (ClamdClient(cfg.clamav.host, cfg.clamav.port, cfg.clamav.timeout)
             if cfg.clamav.enabled and cfg.clamav.host else None)
    return Guard(
        cfg, store,
        QbitClient(cfg.qbittorrent.url, cfg.qbittorrent.username, cfg.qbittorrent.password),
        [ArrClient(a) for a in cfg.arr],
        Scanner(clamd, cfg.clamav.stream_max_mb * 1024 * 1024, cfg.rules.allow_archives, cfg.clamav.scan_media),
        Quarantine(cfg.quarantine_dir, os.path.join(cfg.data_dir, "quarantine-records")),
        background_scans=True,
    )


def create_app(cfg: Config, guard: Guard | None = None, start_worker: bool = True) -> FastAPI:
    guard = guard or build_guard(cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = None
        if start_worker:
            log.info("Protectarr %s starting; settings from %s", __version__, cfg.source)
            try:
                status = await run_checks(guard)
                for s in status["services"]:
                    log.log(logging.INFO if s["ok"] is not False else logging.WARNING,
                            "%s: %s", s["name"], s["detail"])
                for w in status["warnings"]:
                    log.warning("%s", w)
            except Exception:
                log.exception("start-up checks failed")
            try:
                n = await guard.adopt_existing()
                if n:
                    log.info("first run: left %d already-finished torrents alone", n)
            except Exception:
                log.exception("could not reach qBittorrent at startup; will keep retrying")
            task = asyncio.create_task(guard.run_forever())
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Protectarr", version=__version__, lifespan=lifespan)
    app.state.guard = guard
    logins = Logins(guard.store)
    if cfg.reset_login and logins.active:
        logins.reset()
        log.warning("PROTECTARR_RESET_LOGIN is set: the saved username and password were removed. Log in with "
                    "PROTECTARR_API_KEY (or without a password if it isn't set), then remove the variable.")

    def _basic(request: Request) -> tuple[str, str] | None:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("basic "):
            return None
        try:
            user, _, password = base64.b64decode(auth[6:]).decode().partition(":")
            return user, password
        except Exception:
            return "", ""

    def _authorized(request: Request) -> bool:
        login = logins.active
        if not cfg.api_key and not login:
            return True
        # The API key: qBittorrent hooks and scripts (?key= or X-Api-Key). Once you've set your own login, it
        # only opens the JSON API and hooks, not the pages.
        key = request.query_params.get("key") or request.headers.get("x-api-key") or ""
        hook_key = logins.hook_key(cfg.api_key)
        if key and hook_key and hmac.compare_digest(key.encode(), hook_key.encode()) \
                and (not login or request.url.path.startswith("/api/")):
            return True
        creds = _basic(request)
        if creds is None:
            return False
        if login:
            return logins.check(*creds)
        return bool(cfg.api_key) and hmac.compare_digest(creds[1].encode(), cfg.api_key.encode())

    def _same_origin(request: Request) -> bool:
        # Browsers resend Basic credentials on cross-site form posts, so a page elsewhere could press
        # Allow/Restore for you. Browsers always send Origin (or at least Referer) on such posts.
        source = request.headers.get("origin") or request.headers.get("referer")
        if not source:
            return True  # curl, scripts and qBittorrent hooks
        # Behind a reverse proxy the Host header may be the internal one, so accept the forwarded host
        # and PUBLIC_URL too.
        allowed = {request.headers.get("host", ""), request.headers.get("x-forwarded-host", "").split(",")[0].strip(),
                   urlsplit(cfg.public_url).netloc}
        return urlsplit(source).netloc in allowed - {""}

    @app.middleware("http")
    async def guard_requests(request: Request, call_next):
        address = request.client.host if request.client else ""
        if request.url.path != "/health" and not _authorized(request):
            if _basic(request) is not None:  # a wrong password, not just the browser asking
                if logins.blocked(address):
                    return JSONResponse({"detail": "too many failed logins; try again in a few minutes"},
                                        status_code=429)
                logins.failed(address)
            return JSONResponse({"detail": "unauthorized"}, status_code=401,
                                headers={"WWW-Authenticate": 'Basic realm="Protectarr"'})
        if request.method == "POST" and not _same_origin(request):
            return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
        return await call_next(request)

    def page(request: Request, name: str, **ctx):
        return templates.TemplateResponse(request, name, {"version": __version__, "path": request.url.path,
                                                          "pending_count": len(guard.store.pending_decisions()), **ctx})

    @app.get("/health")
    async def health():
        return {"ok": True, "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        clam_ok = await guard.scanner.clamd.ping() if guard.scanner.clamd else None
        events = guard.store.events(100)
        return page(request, "dashboard.html", events=events,
                    blocked=sum(1 for e in events if e["action"].startswith("blocked")),
                    pending=len(guard.store.pending_decisions()), held=len(guard.store.quarantine_items()),
                    clam_ok=clam_ok, watched=sum(1 for c in guard.category_table() if c["watched"]),
                    setup_done=guard.qbit.configured and bool(guard.arrs or guard.cfg.qbittorrent.categories))

    @app.get("/review", response_class=HTMLResponse)
    async def review_page(request: Request, error: str = ""):
        return page(request, "review.html", items=guard.store.pending_decisions(), error=error)

    @app.post("/review/{did}/{choice}")
    async def review(did: int, choice: str):
        if choice not in ("allow", "deny"):
            raise HTTPException(404)
        try:
            await (guard.allow(did) if choice == "allow" else guard.deny(did))
        except LookupError:
            raise HTTPException(404, "no pending decision with that id")
        except Exception as exc:  # e.g. a file can't be moved back, or qBittorrent is down
            log.exception("%s failed", choice)
            return RedirectResponse(f"/review?error={_quote(f'{choice.capitalize()} failed: {exc}')}", status_code=303)
        return RedirectResponse("/review", status_code=303)

    @app.get("/api/review")
    async def review_api():
        return guard.store.pending_decisions()

    @app.get("/quarantine", response_class=HTMLResponse)
    async def quarantine_page(request: Request, error: str = ""):
        # Held downloads are handled on the review page, not here.
        awaiting = {d["quarantine_id"] for d in guard.store.pending_decisions()}
        items = [i for i in guard.store.quarantine_items() if i["id"] not in awaiting]
        for it in items:
            try:
                it["record"] = guard.quarantine.record(it["id"])
            except (FileNotFoundError, ValueError):
                it["record"] = {"files": [], "findings": []}
        return page(request, "quarantine.html", items=items, error=error)

    @app.post("/quarantine/{qid}/restore")
    async def restore(qid: str):
        item = _item(qid)
        try:
            paths = await asyncio.to_thread(guard.quarantine.restore, qid)
        except OSError as exc:
            return RedirectResponse(f"/quarantine?error={_quote(f'Restore failed: {exc}')}", status_code=303)
        guard.store.unblock_hash(item["hash"])
        guard.store.set_quarantine_status(qid, "restored")
        guard.store.log(item["hash"], item["name"], "manual", "clean", f"restored {len(paths)} file(s)", "restored", [])
        return RedirectResponse("/quarantine", status_code=303)

    @app.post("/quarantine/{qid}/delete")
    async def delete(qid: str):
        item = _item(qid)
        try:
            await asyncio.to_thread(guard.quarantine.delete, qid)
        except OSError as exc:
            return RedirectResponse(f"/quarantine?error={_quote(f'Delete failed: {exc}')}", status_code=303)
        guard.store.set_quarantine_status(qid, "deleted")
        guard.store.log(item["hash"], item["name"], "manual", item["level"], "deleted from quarantine", "deleted", [])
        return RedirectResponse("/quarantine", status_code=303)

    def _item(qid: str) -> dict:
        item = guard.store.quarantine_item(qid)
        awaiting = {d["quarantine_id"] for d in guard.store.pending_decisions()}
        if not item or item["status"] != "held" or qid in awaiting:
            raise HTTPException(404, "no such quarantine entry")
        return item

    @app.get("/indexers", response_class=HTMLResponse)
    async def indexers_page(request: Request):
        return page(request, "indexers.html", stats=guard.store.indexer_stats(),
                    prowlarr_url=cfg.prowlarr.url.rstrip("/"))

    @app.get("/api/indexers")
    async def indexers_api():
        return guard.store.indexer_stats()

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request, saved: int = 0, error: str = "", login_error: str = "",
                            login_saved: int = 0):
        status = await run_checks(guard)
        login = logins.get()
        return page(request, "settings.html", status=status, by_name={x["name"]: x for x in status["services"]},
                    conn=connections_of(guard.cfg), kinds=list(ARR_KINDS), hook_base=_hook_base(request),
                    saved=saved, error=error, login_error=login_error, login_saved=login_saved, login_user=(login or {}).get("username", ""),
                    protected=bool(cfg.api_key or login), env_key=bool(cfg.api_key),
                    # A generated key is shown so it can be put in the hooks; PROTECTARR_API_KEY never is.
                    generated_key="" if cfg.api_key else logins.hook_key(""))

    @app.post("/settings/login")
    async def settings_login(request: Request):
        form = {k: v[-1] for k, v in parse_qs((await request.body()).decode(), keep_blank_values=True).items()}
        current, login = form.get("current_password", ""), logins.get()
        if login:
            ok = logins.check(login["username"], current)
        else:
            ok = not cfg.api_key or hmac.compare_digest(current.encode(), cfg.api_key.encode())
        try:
            if not ok:
                raise ValueError("the current password is wrong")
            if form.get("new_password", "") != form.get("confirm_password", ""):
                raise ValueError("the new passwords don't match")
            logins.set(form.get("username", ""), form.get("new_password", ""))
        except ValueError as exc:
            return RedirectResponse(f"/settings?login_error={_quote(str(exc))}#login", status_code=303)
        log.info("the web UI login was changed")
        # The browser's saved login is now wrong, so it asks for the new one.
        return RedirectResponse("/settings?login_saved=1#login", status_code=303)

    @app.post("/settings")
    async def settings_save(request: Request):
        form = {k: v[-1] for k, v in parse_qs((await request.body()).decode(), keep_blank_values=True).items()}
        try:
            await _save_connections(_form_to_connections(form))
        except ValueError as exc:
            return RedirectResponse(f"/settings?error={_quote(str(exc))}", status_code=303)
        return RedirectResponse("/settings?saved=1", status_code=303)

    @app.get("/connections")
    async def connections_redirect():
        return RedirectResponse("/settings", status_code=307)

    @app.get("/api/settings")
    async def settings_api():
        conn = connections_of(guard.cfg)
        conn["qbittorrent"]["password"] = bool(conn["qbittorrent"]["password"])
        conn["prowlarr"]["api_key"] = bool(conn["prowlarr"]["api_key"])
        for a in conn["arr"]:
            a["api_key"] = bool(a["api_key"])
        return conn  # secrets are reported only as set (true) or not (false)

    @app.post("/api/settings")
    async def settings_api_save(request: Request):
        try:
            await _save_connections(await request.json())
        except ValueError as exc:  # also malformed JSON
            raise HTTPException(400, str(exc))
        return await run_checks(guard)

    async def _save_connections(submitted: dict) -> None:
        merged = merge_connections(connections_of(guard.cfg), submitted)
        apply_connections(copy.deepcopy(guard.cfg), merged)  # validate before touching the live settings
        apply_connections(guard.cfg, merged)
        guard.store.set_setting("connections", merged)
        await guard.reconnect()
        log.info("connections updated from the Settings page")

    @app.get("/api/status")
    async def status_api():
        return await run_checks(guard)

    def _hook_base(request: Request) -> str:
        return f"{request.url.scheme}://{request.headers.get('host', 'protectarr:9797')}"

    # qBittorrent "Run external program" hooks. Polling catches anything these miss.
    @app.post("/api/hook/{event}", status_code=202)
    @app.get("/api/hook/{event}", status_code=202)
    async def hook(event: str, hash: str):
        if event not in ("added", "finished"):
            raise HTTPException(404)
        asyncio.create_task(_safe(guard.process_hash(hash.lower())))
        return {"queued": hash}

    @app.get("/api/events")
    async def events(limit: int = 100):
        return guard.store.events(min(limit, 1000))

    @app.get("/api/quarantine")
    async def quarantine_api():
        return guard.store.quarantine_items()

    return app


def _url(value: str) -> str:
    """Accept "your-server-ip:8989" as well as full URLs."""
    value = value.strip().rstrip("/")
    if value and "://" not in value:
        value = "http://" + value
    if value and not urlsplit(value).hostname:
        raise ValueError(f"'{value}' is not a valid address")
    return value


def _int(value: str, what: str) -> int:
    try:
        return int(value.strip())
    except ValueError:
        raise ValueError(f"{what} must be a number")


def _quote(text: str) -> str:
    from urllib.parse import quote
    return quote(text[:200])


def _form_to_connections(f: dict) -> dict:
    out = {
        "qbittorrent": {"url": _url(f.get("qbit_url", "")), "username": f.get("qbit_username", "").strip(),
                        "password": f.get("qbit_password", "")},
        "prowlarr": {"url": _url(f.get("prowlarr_url", "")), "api_key": f.get("prowlarr_api_key", "").strip()},
        "clamav": {"enabled": f.get("clamav_enabled") == "on", "host": f.get("clamav_host", "").strip(),
                   "port": _int(f.get("clamav_port", "3310"), "ClamAV port"),
                   "stream_max_mb": _int(f.get("clamav_stream_max_mb", "25"), "ClamAV size limit")},
        "arr": [],
    }
    if not out["qbittorrent"]["url"]:
        raise ValueError("qBittorrent needs an address")
    rows = sorted({k.split("-")[1] for k in f if k.startswith("arr-")},
                  key=lambda r: (r == "new", int(r) if r.isdigit() else 0))
    for r in rows:
        g = lambda k: f.get(f"arr-{r}-{k}", "").strip()  # noqa: E731
        if g("remove") == "on" or not g("url"):
            continue
        if g("kind") not in ARR_KINDS:
            raise ValueError(f"unknown app type '{g('kind')}'")
        row = {"kind": g("kind"), "name": g("name") or g("kind").capitalize(), "url": _url(g("url")),
               "api_key": g("api_key"), "categories": [c.strip() for c in g("categories").split(",") if c.strip()]}
        if r != "new":
            if not r.isdigit():
                raise ValueError("unexpected form field")
            row["id"] = int(r)
        out["arr"].append(row)
    return out


async def _safe(coro):
    try:
        await coro
    except Exception:
        log.exception("hook processing failed")
