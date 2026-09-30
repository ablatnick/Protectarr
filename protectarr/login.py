"""The web UI's own username and password, set on the Settings page after the first login.

Until one is set, the UI accepts any username with PROTECTARR_API_KEY as the password. Once set, pages need that
username and password, and the API key (or a generated one) only opens /api/ for qBittorrent hooks and scripts."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

ITERATIONS = 600_000
MIN_PASSWORD = 8
# Failed logins per address before it has to wait, and for how long.
MAX_FAILURES = 10
FAILURE_WINDOW_SECONDS = 300


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(got.hex(), digest)
    except (ValueError, TypeError):
        return False


class Logins:
    def __init__(self, store):
        self.store = store
        # Browsers resend Basic credentials with every request; don't re-derive the hash each time.
        self._verified: set[bytes] = set()
        self._failures: dict[str, list[float]] = {}

    def get(self) -> dict | None:
        return self.store.get_setting("login")

    @property
    def active(self) -> bool:
        return self.get() is not None

    def set(self, username: str, password: str) -> None:
        username = username.strip()
        if not username or ":" in username or len(username) > 64:
            raise ValueError("the username must be 1 to 64 characters, without ':'")
        if len(password) < MIN_PASSWORD:
            raise ValueError(f"the password must be at least {MIN_PASSWORD} characters")
        old = self.get() or {}
        self.store.set_setting("login", {
            "username": username, "password": hash_password(password),
            # Hooks and scripts need a key of their own when PROTECTARR_API_KEY isn't set.
            "hook_key": old.get("hook_key") or secrets.token_urlsafe(24), "changed": time.time()})
        self._verified.clear()

    def reset(self) -> None:
        self.store.set_setting("login", None)
        self._verified.clear()

    def _token(self, login: dict, username: str, password: str) -> bytes:
        return hashlib.sha256(f"{login['password']}\0{username}\0{password}".encode()).digest()

    def cached(self, username: str, password: str) -> bool:
        """Already verified since the login was last changed (cheap; no hashing)."""
        login = self.get()
        return bool(login) and self._token(login, username, password) in self._verified

    def check(self, username: str, password: str) -> bool:
        login = self.get()
        if not login:
            return False
        token = self._token(login, username, password)
        if token in self._verified:
            return True
        ok = hmac.compare_digest(username.encode(), login["username"].encode()) and \
            verify_password(password, login["password"])
        if ok:
            self._verified.add(token)
        return ok

    def hook_key(self, api_key: str) -> str:
        login = self.get()
        return api_key or (login or {}).get("hook_key", "")

    # ----- slowing down password guessing ---------------------------------------------------------------------

    def blocked(self, address: str) -> bool:
        now = time.monotonic()
        recent = [t for t in self._failures.get(address, []) if now - t < FAILURE_WINDOW_SECONDS]
        self._failures[address] = recent
        return len(recent) >= MAX_FAILURES

    def failed(self, address: str) -> None:
        self._failures.setdefault(address, []).append(time.monotonic())
