"""Configuration from a YAML file (with ${ENV_VAR} expansion) or from environment variables alone."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ACTIONS = {"block", "hold", "alert"}
PROFILES = {"tv", "movie", "music", "book"}
# kind -> (API version, what its downloads contain)
ARR_KINDS = {
    "sonarr": ("v3", "tv"),
    "radarr": ("v3", "movie"),
    "whisparr": ("v3", "movie"),
    "lidarr": ("v1", "music"),
    "readarr": ("v1", "book"),
}
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_ARR_ENV = re.compile(r"^(" + "|".join(k.upper() for k in ARR_KINDS) + r")(?:_([A-Z0-9]+))?_URL$")


@dataclass
class QbitConfig:
    url: str = ""  # empty until set, so nothing tries to log in with a blank password
    username: str = "admin"
    password: str = ""
    # Only torrents in these categories are checked. Empty means the categories your *arr apps use,
    # read from their download client settings (or every torrent when no *arr app is configured).
    categories: list[str] = field(default_factory=list)
    # Resume torrents that qBittorrent stopped after "Metadata received" once they pass.
    resume_after_metadata_check: bool = True
    # qBittorrent's stop condition applies to every torrent, so also start new torrents in categories
    # Protectarr doesn't check (never ones added more than a couple of minutes ago).
    resume_other_categories: bool = True


@dataclass
class ArrConfig:
    name: str
    url: str
    api_key: str
    kind: str = "sonarr"  # sonarr | radarr | lidarr | readarr | whisparr
    # Categories this app uses in qBittorrent. Empty means read them from the app's download client settings.
    categories: list[str] = field(default_factory=list)

    @property
    def api_version(self) -> str:
        return ARR_KINDS[self.kind][0]

    @property
    def profile(self) -> str:
        return ARR_KINDS[self.kind][1]


@dataclass
class ProwlarrConfig:
    url: str = ""
    api_key: str = ""


@dataclass
class ClamavConfig:
    enabled: bool = True
    host: str = ""  # empty until set
    port: int = 3310
    timeout: float = 120.0
    # clamd's default StreamMaxLength is 25 MB; larger files are not streamed.
    stream_max_mb: int = 25
    # Also scan files that are verified real video/audio (their type is always checked either way).
    scan_media: bool = False


@dataclass
class RulesConfig:
    # Smallest main video file that counts as a real release.
    min_video_mb: int = 30     # episodes, and categories with no known profile
    min_movie_mb: int = 300    # movies (Radarr/Whisparr categories)
    category_min_video_mb: dict[str, int] = field(default_factory=dict)
    # What a category contains when it can't be learned from an *arr app: tv | movie | music | book
    category_profiles: dict[str, str] = field(default_factory=dict)
    # Scene-style RAR releases. Sonarr/Radarr can't import them without an unpacker.
    allow_archives: bool = False
    extra_blocked_extensions: list[str] = field(default_factory=list)


@dataclass
class PathMapping:
    remote: str
    local: str


@dataclass
class Config:
    qbittorrent: QbitConfig = field(default_factory=QbitConfig)
    arr: list[ArrConfig] = field(default_factory=list)
    prowlarr: ProwlarrConfig = field(default_factory=ProwlarrConfig)
    clamav: ClamavConfig = field(default_factory=ClamavConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    path_mappings: list[PathMapping] = field(default_factory=list)
    actions: dict[str, str] = field(default_factory=lambda: {"malicious": "block", "suspicious": "hold"})
    # Check files while they download: each file's real type as soon as its first piece arrives, and a full
    # scan of each file as soon as it finishes. Most bad releases are then caught before the torrent completes,
    # which leaves Sonarr/Radarr almost no window to import them first.
    early_checks: bool = True
    quarantine_dir: str = "/quarantine"
    data_dir: str = "/config"
    poll_seconds: float = 5.0
    apprise_urls: list[str] = field(default_factory=list)
    port: int = 9797
    # Address of the web UI as you open it, used for links in notifications.
    public_url: str = ""
    # When set, the web UI asks for it (HTTP Basic, any username) and hooks must pass ?key=.
    api_key: str = ""
    # Where the settings came from, shown on the Connections page.
    source: str = "defaults"

    def action_for(self, level_label: str) -> str:
        return self.actions.get(level_label, "block")

    def min_video_bytes(self, category: str, profile: str = "tv") -> int:
        if category in self.rules.category_min_video_mb:
            mb = self.rules.category_min_video_mb[category]
        else:
            mb = self.rules.min_movie_mb if profile == "movie" else self.rules.min_video_mb
        return mb * 1024 * 1024

    def to_local(self, path: str) -> str:
        """Translate a path as qBittorrent reports it into a path inside this container."""
        for m in sorted(self.path_mappings, key=lambda m: len(m.remote), reverse=True):
            remote = m.remote.rstrip("/")
            if path == remote or path.startswith(remote + "/"):
                return m.local.rstrip("/") + path[len(remote):]
        return path


def _expand(value):
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def from_dict(raw: dict) -> Config:
    raw = _expand(raw or {})
    cfg = Config(
        qbittorrent=QbitConfig(**raw.get("qbittorrent", {})),
        arr=[ArrConfig(**a) for a in raw.get("arr", []) if a.get("url")],
        prowlarr=ProwlarrConfig(**(raw.get("prowlarr") or {})),
        clamav=ClamavConfig(**raw.get("clamav", {})),
        rules=RulesConfig(**raw.get("rules", {})),
        path_mappings=[PathMapping(**m) for m in raw.get("path_mappings", [])],
    )
    for key in ("quarantine_dir", "data_dir", "poll_seconds", "apprise_urls", "port", "api_key", "public_url",
                "early_checks"):
        if key in raw:
            setattr(cfg, key, raw[key])
    if "actions" in raw:
        cfg.actions.update(raw["actions"])
    _validate(cfg)
    return cfg


def _validate(cfg: Config) -> None:
    bad = {k: v for k, v in cfg.actions.items() if v not in ACTIONS}
    if bad:
        raise ValueError(f"unknown actions {bad}; use one of {sorted(ACTIONS)}")
    names = set()
    for a in cfg.arr:
        if a.kind not in ARR_KINDS:
            raise ValueError(f"arr '{a.name}': kind must be one of {', '.join(ARR_KINDS)}")
        if a.name.lower() in names:
            raise ValueError(f"two apps are called '{a.name}'; give each one its own name (e.g. 'Radarr 4K')")
        names.add(a.name.lower())
    if not 0 < cfg.clamav.port < 65536:
        raise ValueError(f"ClamAV port {cfg.clamav.port} is not a valid port")
    if cfg.clamav.stream_max_mb < 1:
        raise ValueError("ClamAV size limit must be at least 1 MB")
    bad = {k: v for k, v in cfg.rules.category_profiles.items() if v not in PROFILES}
    if bad:
        raise ValueError(f"unknown category profiles {bad}; use one of {sorted(PROFILES)}")


def _list(value: str) -> list[str]:
    return [v.strip() for v in re.split(r"[,\s]+", value or "") if v.strip()]


def _pairs(value: str, sep: str) -> list[tuple[str, str]]:
    out = []
    for item in _list(value):
        if sep not in item:
            raise ValueError(f"expected 'a{sep}b' pairs, got '{item}'")
        a, b = item.split(sep, 1)
        out.append((a.strip(), b.strip()))
    return out


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def from_env(env: dict[str, str] | None = None) -> Config:
    """Build the whole configuration from environment variables (see README, "Environment variables")."""
    env = dict(os.environ if env is None else env)
    g = lambda k, d="": env.get(k, d).strip()  # noqa: E731
    cfg = Config(source="environment variables")

    q = cfg.qbittorrent
    q.url = g("QBIT_URL")
    q.username = g("QBIT_USERNAME", q.username)
    q.password = env.get("QBIT_PASSWORD", "")
    q.categories = _list(g("QBIT_CATEGORIES"))
    if "QBIT_RESUME_AFTER_CHECK" in env:
        q.resume_after_metadata_check = _bool(env["QBIT_RESUME_AFTER_CHECK"])
    if "QBIT_RESUME_OTHER_CATEGORIES" in env:
        q.resume_other_categories = _bool(env["QBIT_RESUME_OTHER_CATEGORIES"])

    # SONARR_URL, SONARR_API_KEY, SONARR_CATEGORIES; extra instances: SONARR_4K_URL, SONARR_4K_API_KEY ...
    for key in sorted(env):
        m = _ARR_ENV.match(key)
        if not m or not env[key].strip():
            continue
        kind, suffix = m.group(1).lower(), m.group(2)
        prefix = key[:-len("_URL")]
        name = kind.capitalize() + (f" {suffix}" if suffix else "")
        cfg.arr.append(ArrConfig(name=name, kind=kind, url=env[key].strip(), api_key=g(f"{prefix}_API_KEY"),
                                 categories=_list(g(f"{prefix}_CATEGORIES"))))

    cfg.prowlarr = ProwlarrConfig(url=g("PROWLARR_URL"), api_key=g("PROWLARR_API_KEY"))

    c = cfg.clamav
    if "CLAMAV_ENABLED" in env:
        c.enabled = _bool(env["CLAMAV_ENABLED"])
    c.host = g("CLAMAV_HOST")
    c.port = int(g("CLAMAV_PORT", str(c.port)))
    c.stream_max_mb = int(g("CLAMAV_STREAM_MAX_MB", str(c.stream_max_mb)))
    c.timeout = float(g("CLAMAV_TIMEOUT", str(c.timeout)))
    if "CLAMAV_SCAN_MEDIA" in env:
        c.scan_media = _bool(env["CLAMAV_SCAN_MEDIA"])

    r = cfg.rules
    r.min_video_mb = int(g("MIN_EPISODE_MB", str(r.min_video_mb)))
    r.min_movie_mb = int(g("MIN_MOVIE_MB", str(r.min_movie_mb)))
    r.category_min_video_mb = {k: int(v) for k, v in _pairs(g("CATEGORY_MIN_VIDEO_MB"), "=")}
    r.category_profiles = dict(_pairs(g("CATEGORY_PROFILES"), "="))
    if "ALLOW_ARCHIVES" in env:
        r.allow_archives = _bool(env["ALLOW_ARCHIVES"])
    r.extra_blocked_extensions = _list(g("EXTRA_BLOCKED_EXTENSIONS"))

    cfg.path_mappings = [PathMapping(a, b) for a, b in _pairs(g("PATH_MAPPINGS"), ":")]
    for level in ("malicious", "suspicious"):
        if g(f"ACTION_{level.upper()}"):
            cfg.actions[level] = g(f"ACTION_{level.upper()}").lower()
    if "EARLY_CHECKS" in env:
        cfg.early_checks = _bool(env["EARLY_CHECKS"])
    cfg.quarantine_dir = g("QUARANTINE_DIR", cfg.quarantine_dir)
    cfg.data_dir = g("DATA_DIR", cfg.data_dir)
    cfg.poll_seconds = float(g("POLL_SECONDS", str(cfg.poll_seconds)))
    cfg.apprise_urls = env.get("APPRISE_URLS", "").split()
    cfg.port = int(g("PORT", str(cfg.port)))
    cfg.public_url = g("PUBLIC_URL")
    cfg.api_key = g("PROTECTARR_API_KEY")
    _validate(cfg)
    return cfg


def load(path: str | None = None) -> Config:
    """Use the config file when it exists, otherwise environment variables."""
    path = path or os.environ.get("PROTECTARR_CONFIG", "/config/config.yml")
    p = Path(path)
    if not p.exists():
        return from_env()
    cfg = from_dict(yaml.safe_load(p.read_text()))
    cfg.source = str(p)
    return cfg


# ----- connections edited in the web UI ------------------------------------------------------------------
# Saved in the database and applied on top of the file/environment settings, so the Settings page wins.

def connections_of(cfg: Config) -> dict:
    """The service connections of cfg, including secrets (for storing, never for display)."""
    return {
        "qbittorrent": {"url": cfg.qbittorrent.url, "username": cfg.qbittorrent.username,
                        "password": cfg.qbittorrent.password},
        "arr": [{"name": a.name, "kind": a.kind, "url": a.url, "api_key": a.api_key, "categories": a.categories}
                for a in cfg.arr],
        "prowlarr": {"url": cfg.prowlarr.url, "api_key": cfg.prowlarr.api_key},
        "clamav": {"enabled": cfg.clamav.enabled, "host": cfg.clamav.host, "port": cfg.clamav.port,
                   "stream_max_mb": cfg.clamav.stream_max_mb},
    }


def apply_connections(cfg: Config, data: dict) -> Config:
    """Apply saved connections to cfg (in place) and return it. Malformed data raises ValueError."""
    if not data:
        return cfg
    try:
        return _apply_connections(cfg, data)
    except (TypeError, KeyError, AttributeError) as exc:
        raise ValueError(f"malformed settings: {exc.__class__.__name__}: {exc}") from None


def _apply_connections(cfg: Config, data: dict) -> Config:
    if not isinstance(data, dict):
        raise TypeError("expected an object")
    q = data.get("qbittorrent") or {}
    for k in ("url", "username", "password"):
        if k in q:
            setattr(cfg.qbittorrent, k, str(q[k]))
    if "arr" in data:
        cfg.arr = [ArrConfig(name=a.get("name") or a["kind"].capitalize(), kind=a["kind"], url=a["url"],
                             api_key=a.get("api_key", ""), categories=list(a.get("categories") or []))
                   for a in data["arr"] if a.get("url")]
    p = data.get("prowlarr") or {}
    for k in ("url", "api_key"):
        if k in p:
            setattr(cfg.prowlarr, k, str(p[k]))
    c = data.get("clamav") or {}
    if "enabled" in c:
        cfg.clamav.enabled = bool(c["enabled"])
    if "host" in c:
        cfg.clamav.host = str(c["host"])
    for k in ("port", "stream_max_mb"):
        if k in c:
            setattr(cfg.clamav, k, int(c[k]))
    _validate(cfg)
    return cfg


def _same_place(a: str, b: str) -> bool:
    from urllib.parse import urlsplit
    ua, ub = urlsplit((a or "").strip().rstrip("/")), urlsplit((b or "").strip().rstrip("/"))
    return (ua.scheme, ua.hostname, ua.port, ua.path) == (ub.scheme, ub.hostname, ub.port, ub.path)


def merge_connections(current: dict, submitted: dict) -> dict:
    """Combine a submitted form with the current connections. A blank password or API key keeps the saved
    one, so secrets never have to be shown in the page. It's only kept for the same address: otherwise
    anyone who can open the page could point a service at their own server and collect the saved secret."""
    try:
        return _merge_connections(current, submitted)
    except (TypeError, KeyError, AttributeError) as exc:
        raise ValueError(f"malformed settings: {exc.__class__.__name__}: {exc}") from None


def _merge_connections(current: dict, submitted: dict) -> dict:
    if not isinstance(submitted, dict) or not all(isinstance(submitted.get(k, {}), dict)
                                                  for k in ("qbittorrent", "prowlarr", "clamav")) \
            or not isinstance(submitted.get("arr", []), list):
        raise TypeError("each section must be an object, and 'arr' a list")
    out = {k: dict(v) if isinstance(v, dict) else v for k, v in current.items()}
    for section, secret, label in (("qbittorrent", "password", None), ("prowlarr", "api_key", "Prowlarr"),
                                   ("clamav", None, None)):
        if section not in submitted:
            continue
        old = current.get(section, {})
        new = dict(submitted[section])
        if secret and not new.get(secret):
            if _same_place(new.get("url", old.get("url", "")), old.get("url", "")):
                new[secret] = old.get(secret, "")
            elif label and new.get("url"):
                raise ValueError(f"{label}'s address changed, so enter its API key again")
            else:
                new[secret] = ""  # qBittorrent may run without a password
        out[section] = {**old, **new}
    if "arr" in submitted:
        old = current.get("arr", [])
        arrs = []
        for a in submitted["arr"]:
            a = dict(a)
            keep = a.pop("id", None)
            if not a.get("api_key"):
                prev = old[int(keep)] if keep is not None and 0 <= int(keep) < len(old) else None
                if prev is None or not _same_place(a.get("url", ""), prev.get("url", "")):
                    name = a.get("name") or a.get("kind", "app").capitalize()
                    raise ValueError(f"{name} needs its API key" + (" again, because its address changed"
                                                                     if prev else ""))
                a["api_key"] = prev.get("api_key", "")
            arrs.append(a)
        out["arr"] = arrs
    return out
