"""Changing the web UI's username and password after the first login."""

import pytest
from fastapi.testclient import TestClient

from protectarr import login as login_mod
from protectarr.login import hash_password, verify_password
from protectarr.web import create_app
from test_guard import env  # noqa: F401  (fixture)


@pytest.fixture(autouse=True)
def fast_hashing(monkeypatch):
    monkeypatch.setattr(login_mod, "ITERATIONS", 1000)
    monkeypatch.setattr(login_mod.hash_password, "__defaults__", (1000,))


def client_for(guard, api_key="first-key"):
    guard.cfg.api_key = api_key
    return TestClient(create_app(guard.cfg, guard, start_worker=False))


def change(c, auth, **form):
    data = {"current_password": "", "username": "", "new_password": "", "confirm_password": "", **form}
    return c.post("/settings/login", data=data, auth=auth, follow_redirects=False)


def test_hashing():
    h = hash_password("correct horse")
    assert "correct horse" not in h and verify_password("correct horse", h)
    assert not verify_password("wrong", h) and not verify_password("x", "garbage")


def test_change_login_after_first_login(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    assert c.get("/", auth=("anyone", "first-key")).status_code == 200  # first login: any username + API key
    page = c.get("/settings", auth=("anyone", "first-key")).text
    assert "Set a login" in page

    r = change(c, ("anyone", "first-key"), current_password="first-key", username="alec",
               new_password="n3w-password", confirm_password="n3w-password")
    assert r.status_code == 303 and "login_saved" in r.headers["location"]

    assert c.get("/", auth=("anyone", "first-key")).status_code == 401  # the old password no longer opens pages
    assert c.get("/", auth=("someone", "n3w-password")).status_code == 401  # username matters now
    assert c.get("/", auth=("alec", "n3w-password")).status_code == 200
    assert "You log in as <b>alec</b>" in c.get("/settings", auth=("alec", "n3w-password")).text
    stored = guard.store.get_setting("login")
    assert "n3w-password" not in str(stored)

    # The API key still works for hooks and the JSON API, but not for pages.
    assert c.get("/api/hook/added?hash=abc&key=first-key").status_code == 202
    assert c.get("/api/events", headers={"x-api-key": "first-key"}).status_code == 200
    assert c.get("/?key=first-key").status_code == 401


def test_change_rejected(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    auth = ("x", "first-key")
    for form, why in [
        ({"current_password": "wrong", "username": "a", "new_password": "longenough", "confirm_password": "longenough"},
         "current password is wrong"),
        ({"current_password": "first-key", "username": "a", "new_password": "longenough", "confirm_password": "other1234"},
         "new passwords don"),
        ({"current_password": "first-key", "username": "a", "new_password": "short", "confirm_password": "short"},
         "at least 8"),
        ({"current_password": "first-key", "username": "a:b", "new_password": "longenough",
          "confirm_password": "longenough"}, "1 to 64 characters"),
    ]:
        r = change(c, auth, **form)
        assert r.status_code == 303 and "login_error" in r.headers["location"]
        assert why in c.get(r.headers["location"], auth=auth).text
    assert guard.store.get_setting("login") is None


def test_change_again_needs_the_new_password(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    change(c, ("x", "first-key"), current_password="first-key", username="alec",
           new_password="password-one", confirm_password="password-one")
    auth = ("alec", "password-one")
    r = change(c, auth, current_password="first-key", username="alec", new_password="password-two",
               confirm_password="password-two")
    assert "login_error" in r.headers["location"]  # the API key isn't the current password any more
    change(c, auth, current_password="password-one", username="ab", new_password="password-two",
           confirm_password="password-two")
    assert c.get("/", auth=("ab", "password-two")).status_code == 200


def test_no_api_key_login_protects_page_and_generates_hook_key(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard, api_key="")
    assert c.get("/").status_code == 200  # open until a login is set
    change(c, None, username="alec", new_password="password-one", confirm_password="password-one")
    assert c.get("/").status_code == 401
    hook_key = guard.store.get_setting("login")["hook_key"]
    assert hook_key in c.get("/settings", auth=("alec", "password-one")).text  # shown so it can go in qBittorrent
    assert c.get(f"/api/hook/added?hash=abc&key={hook_key}").status_code == 202
    assert c.get(f"/?key={hook_key}").status_code == 401


def test_env_api_key_is_never_shown(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard, api_key="very-secret-key")
    assert "very-secret-key" not in c.get("/settings", auth=("x", "very-secret-key")).text


def test_reset_login(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    change(c, ("x", "first-key"), current_password="first-key", username="alec",
           new_password="forgotten-pw", confirm_password="forgotten-pw")
    guard.cfg.reset_login = True
    c = client_for(guard)
    assert c.get("/", auth=("anyone", "first-key")).status_code == 200


def test_password_guessing_is_slowed_down(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    codes = [c.get("/", auth=("x", f"guess{i}")).status_code for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[-1] == 429
    assert c.get("/").status_code == 401  # a browser's first, credential-less request isn't counted or blocked


def test_cross_site_login_change_refused(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    r = c.post("/settings/login", data={"current_password": "first-key", "username": "evil",
                                        "new_password": "evil-pass", "confirm_password": "evil-pass"},
               auth=("x", "first-key"), headers={"origin": "http://evil.example"})
    assert r.status_code == 403 and guard.store.get_setting("login") is None
