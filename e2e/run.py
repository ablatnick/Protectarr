#!/usr/bin/env python3
"""End-to-end test against real qBittorrent, Sonarr, Lidarr, Prowlarr and ClamAV containers.

    python3 e2e/run.py            # build, start, test, and leave the stack running for a look
    python3 e2e/run.py --down     # same, then stop and remove the stack
    E2E_KEEP_WORK=1 ...           # don't wipe e2e/work before starting

Only the standard library is used. Every test torrent is private, has no trackers and contains harmless
files (zeros, text, and the EICAR antivirus test string), so nothing is downloaded from or shared with anyone.
"""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = HERE / "work"
QB, SONARR, LIDARR, PROWLARR, PA = ("http://127.0.0.1:18080", "http://127.0.0.1:18989", "http://127.0.0.1:18686",
                                    "http://127.0.0.1:19696", "http://127.0.0.1:19797")
KEYS = {"sonarr": "e2e0sonarr0000000000000000000001", "lidarr": "e2e0lidarr0000000000000000000001",
        "prowlarr": "e2e0prowlarr00000000000000000001"}
QB_PASSWORD, UI_KEY = "e2e-password", "e2e-ui-key"
MB = 1024 * 1024
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
MKV_HEAD = b"\x1a\x45\xdf\xa3"

results: list[tuple[str, bool, str]] = []


# ----- helpers ---------------------------------------------------------------------------------------------

def compose(*args: str) -> None:
    env = {**os.environ, "E2E_UID": str(os.getuid()), "E2E_GID": str(os.getgid())}
    subprocess.run(["docker", "compose", "-f", str(HERE / "docker-compose.yml"), *args], check=True, env=env)


def request(url: str, data=None, headers=None, method=None, opener=None, timeout=15):
    body = data
    if isinstance(data, dict):
        body = json.dumps(data).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    with (opener or urllib.request.build_opener()).open(req, timeout=timeout) as r:
        raw = r.read()
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def wait(what: str, fn, timeout: float = 300, every: float = 3):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            value = fn()
            if value:
                return value
        except Exception as exc:  # services are still starting
            last = exc
        time.sleep(every)
    raise TimeoutError(f"timed out waiting for {what} ({last!r})")


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{': ' + detail if detail else ''}")


def pa(path: str, method=None, data=None):
    auth = base64.b64encode(f"e2e:{UI_KEY}".encode()).decode()
    return request(PA + path, data=data, method=method, headers={"Authorization": f"Basic {auth}"})


# ----- torrents --------------------------------------------------------------------------------------------

def bencode(o) -> bytes:
    if isinstance(o, int):
        return b"i%de" % o
    if isinstance(o, str):
        o = o.encode()
    if isinstance(o, bytes):
        return b"%d:" % len(o) + o
    if isinstance(o, list):
        return b"l" + b"".join(map(bencode, o)) + b"e"
    return b"d" + b"".join(bencode(k) + bencode(o[k]) for k in sorted(o)) + b"e"


def make_torrent(name: str, files: list[tuple[str, bytes]]) -> tuple[bytes, str]:
    data, piece = b"".join(c for _, c in files), 256 * 1024
    info = {"name": name, "piece length": piece, "private": 1,
            "pieces": b"".join(hashlib.sha1(data[i:i + piece]).digest() for i in range(0, len(data), piece)),
            "files": [{"length": len(c), "path": n.split("/")} for n, c in files]}
    return bencode({"info": info, "created by": "protectarr e2e"}), hashlib.sha1(bencode(info)).hexdigest()


class Qbit:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, path, fields=None, files=None, method=None):
        headers = {"Referer": QB}
        body = None
        if files:
            boundary = "e2eboundary"
            parts = []
            for k, v in (fields or {}).items():
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
            for k, (fname, content) in files.items():
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{fname}"\r\n'
                             f"Content-Type: application/x-bittorrent\r\n\r\n".encode() + content + b"\r\n")
            body = b"".join(parts) + f"--{boundary}--\r\n".encode()
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif fields is not None:
            body = urllib.parse.urlencode(fields).encode()
        return request(QB + "/api/v2" + path, data=body, headers=headers, opener=self.opener, method=method)

    def login(self):
        self.call("/auth/login", {"username": "admin", "password": QB_PASSWORD})
        return self.call("/app/version")

    def add(self, name, files, category, seed_complete=False):
        """Add a test torrent. seed_complete: write the files to disk first and skip the hash check, so
        qBittorrent treats it as finished without downloading anything."""
        blob, h = make_torrent(name, files)
        fields = {"category": category}
        if seed_complete:
            root = WORK / "downloads" / "complete" / category / name
            for rel, content in files:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content)
            fields.update(savepath=f"/downloads/complete/{category}", skip_checking="true")
        self.call("/torrents/add", fields, files={"torrents": (f"{h}.torrent", blob)})
        return h

    def torrent(self, h):
        items = self.call(f"/torrents/info?hashes={h}")
        return items[0] if items else None


# ----- setup -----------------------------------------------------------------------------------------------

def seed_configs() -> None:
    if WORK.exists() and not os.environ.get("E2E_KEEP_WORK"):
        shutil.rmtree(WORK)
    for d in ("qbittorrent/qBittorrent", "sonarr", "lidarr", "prowlarr", "protectarr", "quarantine",
              "downloads/complete", "downloads/incomplete"):
        (WORK / d).mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha512", QB_PASSWORD.encode(), salt, 100000, 64)
    pw = f"@ByteArray({base64.b64encode(salt).decode()}:{base64.b64encode(digest).decode()})"
    (WORK / "qbittorrent/qBittorrent/qBittorrent.conf").write_text(f"""[BitTorrent]
Session\\DefaultSavePath=/downloads/complete
Session\\TempPath=/downloads/incomplete
Session\\TempPathEnabled=true
Session\\TorrentStopCondition=MetadataReceived
Session\\DHTEnabled=false
Session\\PeXEnabled=false
Session\\LSDEnabled=false

[LegalNotice]
Accepted=true

[Preferences]
WebUI\\Username=admin
WebUI\\Password_PBKDF2="{pw}"
WebUI\\HostHeaderValidation=false
""")
    for app, port in (("sonarr", 8989), ("lidarr", 8686), ("prowlarr", 9696)):
        (WORK / app / "config.xml").write_text(
            f"<Config><ApiKey>{KEYS[app]}</ApiKey><Port>{port}</Port><BindAddress>*</BindAddress>"
            "<AuthenticationMethod>External</AuthenticationMethod>"
            "<AuthenticationRequired>DisabledForLocalAddresses</AuthenticationRequired>"
            "<UrlBase></UrlBase><LogLevel>info</LogLevel><AnalyticsEnabled>False</AnalyticsEnabled></Config>")


def add_download_client(url: str, api: str, key: str, category_field: str, category: str) -> None:
    body = {"enable": True, "protocol": "torrent", "priority": 1, "name": "qBittorrent",
            "implementation": "QBittorrent", "configContract": "QBittorrentSettings", "tags": [],
            "fields": [{"name": "host", "value": "qbittorrent"}, {"name": "port", "value": 8080},
                       {"name": "username", "value": "admin"}, {"name": "password", "value": QB_PASSWORD},
                       {"name": category_field, "value": category}]}
    request(f"{url}/api/{api}/downloadclient?forceSave=true", data=body, headers={"X-Api-Key": key})


def event_for(name: str, predicate=lambda e: True):
    return next((e for e in pa("/api/events?limit=200") if e["name"] == name and predicate(e)), None)


# ----- scenarios -------------------------------------------------------------------------------------------

def main() -> int:
    print("== seeding config folders")
    compose("down", "--remove-orphans")  # a previous run's containers hold the folders open
    seed_configs()
    print("== building and starting the stack (first run pulls images; ClamAV then needs a few minutes)")
    compose("up", "-d", "--build")

    q = Qbit()
    version = wait("qBittorrent", q.login, 180)
    print(f"   qBittorrent {version}")
    for app, url, api in (("sonarr", SONARR, "v3"), ("lidarr", LIDARR, "v1"), ("prowlarr", PROWLARR, "v1")):
        wait(app, lambda: request(f"{url}/api/{api}/system/status", headers={"X-Api-Key": KEYS[app]}), 300)
    print("== connecting Sonarr and Lidarr to qBittorrent (as a user would in their Settings > Download Clients)")
    add_download_client(SONARR, "v3", KEYS["sonarr"], "tvCategory", "tv-sonarr")
    add_download_client(LIDARR, "v1", KEYS["lidarr"], "musicCategory", "music")

    print("== entering every service on Protectarr's Settings page")
    wait("Protectarr", lambda: request(PA + "/health")["ok"], 300)
    fresh = pa("/api/status")
    check("fresh install watches nothing until an *arr app is added",
          not fresh["categories"] and not fresh["setup_done"])
    form = {"qbit_url": "qbittorrent:8080", "qbit_username": "admin", "qbit_password": QB_PASSWORD,
            "clamav_enabled": "on", "clamav_host": "clamav", "clamav_port": "3310", "clamav_stream_max_mb": "25",
            "prowlarr_url": "http://prowlarr:9696", "prowlarr_api_key": KEYS["prowlarr"],
            "arr-new-kind": "sonarr", "arr-new-url": "sonarr:8989", "arr-new-api_key": KEYS["sonarr"]}
    pa("/settings", method="POST", data=urllib.parse.urlencode(form).encode())
    # A second save, as the page would send it: the saved Sonarr row with its key left blank, plus Lidarr.
    form.update({"qbit_password": "", "prowlarr_api_key": "",
                 "arr-0-kind": "sonarr", "arr-0-name": "Sonarr", "arr-0-url": "http://sonarr:8989", "arr-0-api_key": "",
                 "arr-new-kind": "lidarr", "arr-new-url": "http://lidarr:8686", "arr-new-api_key": KEYS["lidarr"]})
    pa("/settings", method="POST", data=urllib.parse.urlencode(form).encode())
    saved = pa("/api/settings")
    check("settings saved through the form, secrets kept and never shown",
          [a["name"] for a in saved["arr"]] == ["Sonarr", "Lidarr"] and all(a["api_key"] is True for a in saved["arr"])
          and saved["qbittorrent"]["password"] is True and KEYS["sonarr"] not in json.dumps(saved)
          and KEYS["sonarr"] not in pa("/settings"), json.dumps(saved["arr"]))

    print("== waiting for ClamAV")
    status = wait("ClamAV signatures", lambda: (s := pa("/api/status")) and
                  all(x["ok"] for x in s["services"]) and s, 900, 10)

    print("== connections")
    for s in status["services"]:
        check(f"connection: {s['name']}", s["ok"], s["detail"])
    cats = {c["category"]: c for c in status["categories"]}
    check("categories read from Sonarr and Lidarr",
          cats.get("tv-sonarr", {}).get("source") == "Sonarr" and cats.get("music", {}).get("profile") == "music",
          ", ".join(f"{k}={v['profile']} via {v['source']}" for k, v in cats.items()))

    print("== scenarios")
    video = MKV_HEAD + b"\0" * (31 * MB)

    n1 = "E2E.Show.S01E01.1080p.WEB.H264-TEST"
    h1 = q.add(n1, [(f"{n1}.mkv.exe", b"harmless text, not a program\n" * 40)], "tv-sonarr")
    e = wait("bait blocked", lambda: event_for(n1), 60, 1)
    wait("bait removed", lambda: q.torrent(h1) is None, 30, 1)
    check("1. program disguised as .mkv.exe blocked before download",
          e["level"] == "malicious" and e["stage"] == "metadata" and e["action"].startswith("blocked"), e["action"])

    n2 = "E2E.Show.S01E02.1080p.WEB.H264-TEST"
    h2 = q.add(n2, [(f"{n2}.mkv", MKV_HEAD + b"\0" * (2 * MB))], "tv-sonarr")
    d = wait("tiny episode held", lambda: next((x for x in pa("/api/review") if x["name"] == n2), None), 60, 1)
    t = q.torrent(h2)
    check("2a. 2 MB 'episode' held for review", t and "protectarr-held" in t["tags"], d["summary"])
    pa(f"/review/{d['id']}/deny", method="POST", data=b"")
    wait("denied torrent removed", lambda: q.torrent(h2) is None, 30, 1)
    e = event_for(n2, lambda e: e["action"].startswith("denied"))
    check("2b. Deny removes and blocklists it", bool(e), e["action"] if e else "no event")

    n3 = "E2E.Show.S01E03.1080p.WEB.H264-TEST"
    q.add(n3, [(f"{n3}/{n3}.mkv", b"MZ" + b"\0" * (40 * MB))], "tv-sonarr", seed_complete=True)
    e = wait("disguised program quarantined", lambda: event_for(n3, lambda e: e["stage"] == "content"), 120, 1)
    gone = not (WORK / "downloads/complete/tv-sonarr" / n3 / f"{n3}.mkv").exists()
    check("3. program with a .mkv name caught after download and quarantined",
          e["level"] == "malicious" and "quarantined" in e["action"] and gone, e["summary"])

    n4 = "E2E.Show.S01E04.1080p.WEB.H264-TEST"
    q.add(n4, [(f"{n4}/{n4}.mkv", video), (f"{n4}/readme.txt", EICAR)],
          "tv-sonarr", seed_complete=True)
    e = wait("EICAR caught", lambda: event_for(n4, lambda e: e["stage"] == "content"), 180, 2)
    # ClamAV only matches the EICAR test string at the very start of a file.
    check("4. ClamAV detects the EICAR test file in an extra .txt", e["level"] == "malicious" and "ClamAV" in
          e["summary"], e["summary"])

    n5 = "E2E.Artist-Album-2026-FLAC"
    h5 = q.add(n5, [(f"{n5}/01-track.flac", b"fLaC" + b"\0" * (3 * MB)), (f"{n5}/album.cue", b"FILE x WAVE\n"),
                    (f"{n5}/rip.log", b"EAC log\n"), (f"{n5}/cover.jpg", b"\xff\xd8\xff\xe0" + b"\0" * 100)],
               "music", seed_complete=True)
    e = wait("album checked", lambda: event_for(n5, lambda e: e["stage"] == "content"), 120, 1)
    check("5. clean FLAC album (Lidarr category) passes with music rules",
          e["level"] == "clean" and q.torrent(h5) is not None, e["action"])

    n6 = "E2E.Some.Linux.Tool"
    h6 = q.add(n6, [(f"{n6}/setup.exe", b"harmless\n")], "software")
    started = wait("other category started", lambda: not q.torrent(h6)["state"].startswith("stopped"), 30, 1)
    check("6. torrents outside the *arr categories aren't checked, but still start despite the stop condition",
          event_for(n6) is None and started, q.torrent(h6)["state"])

    q.add("E2E.Show.S01E05.1080p.WEB.H264-TEST", [("E2E.Show.S01E05.1080p.WEB.H264-TEST.mkv", video)], "tv-sonarr")
    e = wait("clean release", lambda: event_for("E2E.Show.S01E05.1080p.WEB.H264-TEST"), 60, 1)
    h7 = make_torrent("E2E.Show.S01E05.1080p.WEB.H264-TEST", [("E2E.Show.S01E05.1080p.WEB.H264-TEST.mkv", video)])[1]
    try:  # qBittorrent may stop it just after the check; Protectarr starts it on its next poll
        wait("clean episode started", lambda: not q.torrent(h7)["state"].startswith("stopped"), 20, 1)
    except TimeoutError:
        pass
    t = q.torrent(h7)
    check("7. clean episode passes and is started again after the metadata stop",
          e["level"] == "clean" and t and not t["state"].startswith("stopped"), f"state {t and t['state']}")

    r = urllib.request.Request(PA + "/review/1/allow", method="POST", data=b"",
                               headers={"Origin": "https://evil.example",
                                        "Authorization": "Basic " + base64.b64encode(f"x:{UI_KEY}".encode()).decode()})
    try:
        urllib.request.urlopen(r, timeout=10)
        code = 200
    except urllib.error.HTTPError as exc:
        code = exc.code
    check("8. cross-site POST refused", code == 403, f"HTTP {code}")
    try:
        urllib.request.urlopen(PA + "/", timeout=10)
        code = 200
    except urllib.error.HTTPError as exc:
        code = exc.code
    check("9. UI requires the password", code == 401, f"HTTP {code}")

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n== {len(results) - len(failed)}/{len(results)} passed")
    print(f"   UI: {PA}  (any username, password {UI_KEY})")
    if "--down" in sys.argv:
        compose("down")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
