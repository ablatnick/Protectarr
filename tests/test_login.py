"""The web UI login, the API token and the hook token."""

import logging

from fastapi.testclient import TestClient

from conftest import FIRST_PASSWORD
from protectarr.login import hash_password, verify_password
from protectarr.web import create_app
from test_guard import env  # noqa: F401  (fixture)

FIRST = ("admin", FIRST_PASSWORD)


def client_for(guard, api_key="", password=""):
    guard.cfg.api_key, guard.cfg.password = api_key, password
    return TestClient(create_app(guard.cfg, guard, start_worker=False))


def change(c, auth, **form):
    data = {"current_password": "", "username": "", "new_password": "", "confirm_password": "", **form}
    return c.post("/settings/login", data=data, auth=auth, follow_redirects=False)


def test_hashing():
    h = hash_password("correct horse")
    assert "correct horse" not in h and verify_password("correct horse", h)
    assert not verify_password("wrong", h) and not verify_password("x", "garbage")


def test_first_start_generates_a_password_and_logs_it_once(env, caplog):  # noqa: F811
    guard, *_ = env
    with caplog.at_level(logging.WARNING):
        c = client_for(guard)
    assert FIRST_PASSWORD in caplog.text
    assert c.get("/").status_code == 401
    assert c.get("/", auth=("someone", FIRST_PASSWORD)).status_code == 401  # the username matters
    assert c.get("/", auth=FIRST).status_code == 200
    assert "generated on first start" in c.get("/settings", auth=FIRST).text
    assert FIRST_PASSWORD not in str(guard.store.get_setting("login"))
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        client_for(guard)
    assert FIRST_PASSWORD not in caplog.text  # only printed when it's made


def test_first_password_from_the_environment(env, caplog):  # noqa: F811
    guard, *_ = env
    guard.cfg.username = "ab"
    with caplog.at_level(logging.WARNING):
        c = client_for(guard, password="my-own-password")
    assert "my-own-password" not in caplog.text
    assert c.get("/", auth=("ab", "my-own-password")).status_code == 200
    assert "generated on first start" not in c.get("/settings", auth=("ab", "my-own-password")).text


def test_too_short_first_password_falls_back_to_a_generated_one(env, caplog):  # noqa: F811
    guard, *_ = env
    with caplog.at_level(logging.WARNING):
        c = client_for(guard, password="short")
    assert "at least 8" in caplog.text and FIRST_PASSWORD in caplog.text
    assert c.get("/", auth=FIRST).status_code == 200


def test_change_login(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    r = change(c, FIRST, current_password=FIRST_PASSWORD, username="owner",
               new_password="n3w-password", confirm_password="n3w-password")
    assert r.status_code == 303 and "login_saved" in r.headers["location"]
    assert c.get("/", auth=FIRST).status_code == 401
    assert c.get("/", auth=("owner", "n3w-password")).status_code == 200
    page = c.get("/settings", auth=("owner", "n3w-password")).text
    assert "You log in as <b>owner</b>" in page and "generated on first start" not in page
    assert "n3w-password" not in str(guard.store.get_setting("login"))
    r = change(c, ("owner", "n3w-password"), current_password=FIRST_PASSWORD, username="owner",
               new_password="password-two", confirm_password="password-two")
    assert "login_error" in r.headers["location"]  # the old password isn't the current one any more


def test_change_rejected(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    for form, why in [
        ({"current_password": "wrong", "username": "a", "new_password": "longenough", "confirm_password": "longenough"},
         "current password is wrong"),
        ({"current_password": FIRST_PASSWORD, "username": "a", "new_password": "longenough",
          "confirm_password": "other1234"}, "new passwords don"),
        ({"current_password": FIRST_PASSWORD, "username": "a", "new_password": "short", "confirm_password": "short"},
         "at least 8"),
        ({"current_password": FIRST_PASSWORD, "username": "a:b", "new_password": "longenough",
          "confirm_password": "longenough"}, "1 to 64 characters"),
    ]:
        r = change(c, FIRST, **form)
        assert r.status_code == 303 and "login_error" in r.headers["location"]
        assert why in c.get(r.headers["location"], auth=FIRST).text
    assert guard.store.get_setting("login")["generated"]


def test_tokens_only_open_what_they_are_for(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    api, hook = guard.store.get_setting("api_key"), guard.store.get_setting("hook_key")
    assert api and hook and api != hook
    page = c.get("/settings", auth=FIRST).text
    assert api in page and hook in page and f"Bearer {hook}" in page
    # API token: the JSON API, as a header only, never pages.
    assert c.get("/api/events", headers={"Authorization": f"Bearer {api}"}).status_code == 200
    assert c.get("/api/events", headers={"X-Api-Key": api}).status_code == 200
    assert c.get(f"/api/events?key={api}").status_code == 401
    assert c.get("/", headers={"Authorization": f"Bearer {api}"}).status_code == 401
    assert c.get("/", auth=("x", api)).status_code == 401
    # Hook token: only the hooks.
    assert c.get("/api/hook/added?hash=abc", headers={"Authorization": f"Bearer {hook}"}).status_code == 202
    assert c.get(f"/api/hook/finished?hash=abc&key={hook}").status_code == 202
    assert c.get("/api/events", headers={"Authorization": f"Bearer {hook}"}).status_code == 401
    assert c.get("/api/settings", headers={"X-Api-Key": hook}).status_code == 401
    assert c.get("/", auth=("x", hook)).status_code == 401


def test_regenerate_token(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    old = guard.store.get_setting("hook_key")
    assert c.post("/settings/token/hook_key", auth=FIRST, follow_redirects=False).status_code == 303
    new = guard.store.get_setting("hook_key")
    assert new != old
    assert c.get(f"/api/hook/added?hash=abc&key={old}").status_code == 401
    assert c.get(f"/api/hook/added?hash=abc&key={new}").status_code == 202
    assert c.post("/settings/token/login", auth=FIRST).status_code == 404
    assert c.post("/settings/token/hook_key").status_code == 401


def test_env_api_key_is_never_shown_or_regenerated(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard, api_key="very-secret-key")
    assert "very-secret-key" not in c.get("/settings", auth=FIRST).text
    assert c.get("/api/events", headers={"X-Api-Key": "very-secret-key"}).status_code == 200
    assert c.post("/settings/token/api_key", auth=FIRST).status_code == 404


def test_older_setups_keep_working(env, caplog):  # noqa: F811
    guard, *_ = env
    # Earlier versions kept the hook key with the login, and hooks passed the API key in the URL.
    guard.store.set_setting("login", {"username": "owner", "password": hash_password("old-password"),
                                      "hook_key": "old-hook-key"})
    c = client_for(guard, api_key="env-key")
    assert c.get("/", auth=("owner", "old-password")).status_code == 200
    assert c.get("/api/hook/added?hash=abc&key=old-hook-key").status_code == 202
    with caplog.at_level(logging.WARNING):
        assert c.get("/api/hook/added?hash=abc&key=env-key").status_code == 202
    assert "hook token" in caplog.text


def test_reset_login(env, caplog):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    change(c, FIRST, current_password=FIRST_PASSWORD, username="owner",
           new_password="forgotten-pw", confirm_password="forgotten-pw")
    guard.cfg.reset_login = True
    with caplog.at_level(logging.WARNING):
        c = client_for(guard)
    assert FIRST_PASSWORD in caplog.text  # a new password, printed in the log
    assert c.get("/", auth=FIRST).status_code == 200
    assert c.get("/", auth=("owner", "forgotten-pw")).status_code == 401


def test_password_guessing_is_slowed_down(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    codes = [c.get("/", auth=("x", f"guess{i}")).status_code for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[-1] == 429
    assert c.get("/").status_code == 401  # a browser's first, credential-less request isn't counted or blocked


def test_cross_site_login_change_refused(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    r = c.post("/settings/login", data={"current_password": FIRST_PASSWORD, "username": "evil",
                                        "new_password": "evil-pass", "confirm_password": "evil-pass"},
               auth=FIRST, headers={"origin": "http://evil.example"})
    assert r.status_code == 403 and guard.store.get_setting("login")["username"] == "admin"
    r = c.post("/settings/token/hook_key", auth=FIRST, headers={"origin": "http://evil.example"})
    assert r.status_code == 403


def test_locked_out_address_cannot_find_the_right_password(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    for i in range(10):
        assert c.get("/", auth=("admin", f"guess{i}")).status_code == 401
    # Locked: even the right password is refused, so guessing can't continue in the background.
    assert c.get("/", auth=FIRST).status_code == 429


def test_wrong_tokens_count_as_failed_logins(env):  # noqa: F811
    guard, *_ = env
    c = client_for(guard)
    codes = [c.get("/api/events", headers={"Authorization": f"Bearer guess{i}"}).status_code for i in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429


def test_pages_cannot_be_framed_by_other_sites(env):  # noqa: F811
    guard, _, _, _ = env
    c = client_for(guard)
    for r in (c.get("/"), c.get("/", auth=FIRST), c.get("/health")):
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["Content-Security-Policy"] == "frame-ancestors 'none'"
        assert r.headers["X-Content-Type-Options"] == "nosniff"
