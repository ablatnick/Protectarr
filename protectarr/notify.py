"""Send alerts through Apprise (Discord, Telegram, ntfy, email, and many more)."""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, urls: list[str]):
        self.apprise = None
        if urls:
            import apprise

            self.apprise = apprise.Apprise()
            for u in urls:
                self.apprise.add(u)

    async def send(self, title: str, body: str) -> None:
        log.info("%s: %s", title, body)
        if self.apprise is not None:
            try:
                await asyncio.to_thread(self.apprise.notify, title=title, body=body)
            except Exception as exc:  # notifications must never break scanning
                log.warning("notification failed: %s", exc)
