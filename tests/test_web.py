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
