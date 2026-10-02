from fastapi.testclient import TestClient

from conftest import DEFAULT_LOGIN, FIRST_PASSWORD
from protectarr.config import from_dict
from protectarr.web import create_app
from test_guard import env  # noqa: F401  (fixture)


def test_pages_and_auth(env):  # noqa: F811
    guard, qb, _, _ = env
    guard.store.log("x", "Some.Release", "metadata", "malicious", "program file", "blocked: removed", [
        {"level": "malicious", "code": "executable", "message": "program file 'a.exe'", "path": "a.exe"}])
    guard.cfg.api_key = "s3cret"
    client = TestClient(create_app(guard.cfg, guard, start_worker=False))
    login = ("admin", FIRST_PASSWORD)
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("any", "s3cret")).status_code == 401  # the API token never opens pages
    r = client.get("/", auth=login)
    assert r.status_code == 200 and "Some.Release" in r.text
    assert client.get("/quarantine", auth=login).status_code == 200
    assert "Nothing is waiting" in client.get("/review", auth=login).text
    assert client.post("/review/99/allow", auth=login).status_code == 404
    bearer = {"Authorization": "Bearer s3cret"}
    assert client.get("/api/hook/added?hash=abc", headers=bearer).status_code == 202
    assert client.get("/api/hook/nope?hash=abc", headers=bearer).status_code == 404
    assert client.get("/api/hook/added?hash=abc&key=s3cret").status_code == 202  # older hook setups


def test_config_env_expansion(monkeypatch):
    monkeypatch.setenv("QBP", "pw")
    cfg = from_dict({"qbittorrent": {"password": "${QBP}"},
                     "path_mappings": [{"remote": "/downloads", "local": "/data"}]})
    assert cfg.qbittorrent.password == "pw"
    assert cfg.to_local("/downloads/a/b.mkv") == "/data/a/b.mkv"
    assert cfg.to_local("/downloadsX/a") == "/downloadsX/a"


def test_review_page_allow(env):  # noqa: F811
    import asyncio
    guard, qb, _, _ = env
    qb.add("mmm", "Odd.Release", [("Odd.Release.mkv", 1024)])
    asyncio.run(guard.poll())
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    page = client.get("/review").text
    assert "Odd.Release" in page and "below the" in page
    [d] = guard.store.pending_decisions()
    r = client.post(f"/review/{d['id']}/allow", follow_redirects=False)
    assert r.status_code == 303 and not guard.store.pending_decisions()


def test_allowed_file_types_setting(env):  # noqa: F811
    guard, qb, _, _ = env
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    r = client.post("/settings/rules", data={"allowed_extensions": "ISO, .mka thing"}, follow_redirects=False)
    assert r.status_code == 303 and "rules_saved=1" in r.headers["location"]
    assert guard.cfg.rules.allowed_extensions == [".iso", ".mka", ".thing"]
    assert guard.scanner.allowed_extensions == {".iso", ".mka", ".thing"}
    assert guard.store.get_setting("rules")["allowed_extensions"] == [".iso", ".mka", ".thing"]
    page = client.get("/settings").text
    assert ".iso, .mka, .thing" in page and "Program files are allowed" not in page

    r = client.post("/settings/rules", data={"allowed_extensions": "*.exe"}, follow_redirects=False)
    assert "rules_error=" in r.headers["location"] and guard.cfg.rules.allowed_extensions == [".iso", ".mka", ".thing"]
    guard.cfg.rules.extra_blocked_extensions = [".iso"]
    r = client.post("/settings/rules", data={"allowed_extensions": ".iso"}, follow_redirects=False)
    assert "both%20allowed%20and%20blocked" in r.headers["location"]
    guard.cfg.rules.extra_blocked_extensions = []

    client.post("/settings/rules", data={"allowed_extensions": ".exe"})
    assert "Program files are allowed (.exe)" in client.get("/settings").text

    # A torrent that would be held for its file types now passes.
    client.post("/settings/rules", data={"allowed_extensions": ".iso"})
    import asyncio
    qb.add("iii", "Movie.With.Extras", [("Movie.mkv", 900 * 1024 * 1024), ("extras.iso", 4096)])
    asyncio.run(guard.poll())
    assert not guard.store.pending_decisions()

    client.post("/settings/rules", data={"allowed_extensions": ""})
    assert guard.cfg.rules.allowed_extensions == [] and guard.scanner.allowed_extensions == set()


def test_allowed_file_types_api(env):  # noqa: F811
    guard, _, _, _ = env
    guard.cfg.api_key = "tok"
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers={"Authorization": "Bearer tok"})
    assert client.get("/api/rules").json() == {"allowed_extensions": [], "history_days": 90}
    assert client.post("/api/rules", json={"allowed_extensions": ["MKA"]}).json()["allowed_extensions"] == [".mka"]
    assert client.post("/api/rules", json={"history_days": 30}).json() == {"allowed_extensions": [".mka"],
                                                                         "history_days": 30}
    assert client.post("/api/rules", json={"history_days": -1}).status_code == 400
    assert client.post("/api/rules", json={"history_days": "7"}).status_code == 400
    assert client.post("/api/rules", json={"allowed_extensions": "mka"}).status_code == 400
    assert client.post("/api/rules", json=["x"]).status_code == 400


def test_allowed_file_types_from_config_and_env():
    from protectarr.config import from_env
    assert from_dict({"rules": {"allowed_extensions": ["ISO", "mka"]}}).rules.allowed_extensions == [".iso", ".mka"]
    assert from_env({"ALLOWED_EXTENSIONS": ".iso, mka"}).rules.allowed_extensions == [".iso", ".mka"]
    import pytest
    with pytest.raises(ValueError):
        from_dict({"rules": {"allowed_extensions": [".iso"], "extra_blocked_extensions": ["iso"]}})


def test_activity_paging(env):  # noqa: F811
    guard, _, _, _ = env
    for i in range(250):
        guard.store.log(f"h{i}", f"Release.{i:03d}", "metadata", "clean", "clean", "allow", [])
    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    first = client.get("/").text
    assert "Release.249" in first and "Release.150" in first and "Release.149" not in first
    older = first.split('href="/?before=')[1].split('"')[0]
    second = client.get(f"/?before={older}").text
    assert "Release.149" in second and "Release.050" in second and "Release.249" not in second and "Newest" in second
    third = client.get("/?before=" + second.split('href="/?before=')[1].split('"')[0]).text
    assert "Release.000" in third and "Release.049" in third and "/?before=" not in third  # last page
    assert "No older results" in client.get("/?before=1").text
    api = client.get("/api/events?limit=2").json()
    assert [e["name"] for e in api] == ["Release.249", "Release.248"]
    assert [e["name"] for e in client.get(f"/api/events?limit=2&before={api[-1]['id']}").json()] == \
        ["Release.247", "Release.246"]


def test_history_cleanup(env):  # noqa: F811
    guard, _, _, _ = env
    old = 1_000_000.0
    for name, level, action in (("Old.Clean", "clean", "allow"), ("Old.Blocked", "malicious", "blocked: removed"),
                                ("Old.Held", "suspicious", "held for your decision")):
        guard.store.log("x", name, "metadata", level, "", action, [], "SomeIndexer")
        guard.store._exec("UPDATE events SET ts=? WHERE name=?", (old, name))
    guard.store.log("y", "New.Clean", "metadata", "clean", "", "allow", [])
    stats = guard.store.indexer_stats()
    guard.cfg.history_days = 0
    assert guard.prune_history() == 0  # 0 keeps everything
    guard.cfg.history_days = 90
    assert guard.prune_history() == 1
    assert {e["name"] for e in guard.store.events()} == {"Old.Blocked", "Old.Held", "New.Clean"}
    assert guard.store.indexer_stats() == stats

    client = TestClient(create_app(guard.cfg, guard, start_worker=False), headers=DEFAULT_LOGIN)
    assert "kept for 90 days" in client.get("/").text
    r = client.post("/settings/history", data={"history_days": "0"}, follow_redirects=False)
    assert "history_saved=1" in r.headers["location"] and guard.cfg.history_days == 0
    assert "All results are kept" in client.get("/").text
    for bad in ("-3", "soon", ""):
        r = client.post("/settings/history", data={"history_days": bad}, follow_redirects=False)
        assert "history_error=" in r.headers["location"] and guard.cfg.history_days == 0
    assert guard.store.get_setting("rules")["history_days"] == 0


def test_history_days_from_config_and_env():
    from protectarr.config import from_env
    assert from_dict({}).history_days == 90
    assert from_dict({"history_days": 7}).history_days == 7
    assert from_env({"HISTORY_DAYS": "0"}).history_days == 0
    import pytest
    with pytest.raises(ValueError):
        from_dict({"history_days": -1})
