"""Protectarr's three credentials, kept apart so a leaked one only opens what it's for.

- **Web UI login** (username + password, stored as a salted PBKDF2 hash). On first start it comes from
  PROTECTARR_USERNAME/PROTECTARR_PASSWORD, or a random password is generated and printed once in the log. Change it
  on the Settings page. It opens everything.
- **API token** (PROTECTARR_API_KEY, or generated): scripts and the JSON API under /api/, sent as a header.
- **Hook token** (generated): only the qBittorrent hooks under /api/hook/. It sits in qBittorrent's settings and
  may end up in logs, so it can't open anything else."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

ITERATIONS = 600_000
MIN_PASSWORD = 8
DEFAULT_USERNAME = "admin"
# Failed logins per address before it has to wait, and for how long.
MAX_FAILURES = 10
FAILURE_WINDOW_SECONDS = 300


def new_secret(nbytes: int = 18) -> str:
    return secrets.token_urlsafe(nbytes)


def new_password() -> str:
    return new_secret(12)


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
        self._save(username, password, generated=False)

    def _save(self, username: str, password: str, generated: bool) -> None:
        self.store.set_setting("login", {"username": username, "password": hash_password(password),
                                         "generated": generated, "changed": time.time()})
        self._verified.clear()

    @property
    def generated(self) -> bool:
        """Still the password Protectarr made up on first start."""
        return bool((self.get() or {}).get("generated"))

    def ensure(self, username: str = "", password: str = "") -> str | None:
        """Create the first login if there's none: from the given password, or a random one, which is returned
        so it can be printed once."""
        if self.active:
            return None
        username = username.strip() or DEFAULT_USERNAME
        if password:
            self.set(username, password)
            return None
        password = new_password()
        self._save(username, password, generated=True)
        return password

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

    # ----- tokens for scripts and hooks ----------------------------------------------------------------------

    def token(self, name: str) -> str:
        """The generated "api_key" or "hook_key", created on first use."""
        value = self.store.get_setting(name)
        if not value:
            # Earlier versions kept the hook key with the login; keep it so existing hooks still work.
            value = (name == "hook_key" and (self.get() or {}).get("hook_key")) or new_secret()
            self.store.set_setting(name, value)
        return value

    def regenerate(self, name: str) -> str:
        value = new_secret()
        self.store.set_setting(name, value)
        return value

    # ----- slowing down password guessing ---------------------------------------------------------------------

    def blocked(self, address: str) -> bool:
        now = time.monotonic()
        recent = [t for t in self._failures.get(address, []) if now - t < FAILURE_WINDOW_SECONDS]
        self._failures[address] = recent
        return len(recent) >= MAX_FAILURES

    def failed(self, address: str) -> None:
        self._failures.setdefault(address, []).append(time.monotonic())
