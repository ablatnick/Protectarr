"""Minimal async client for clamd (INSTREAM and PING)."""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

CHUNK = 64 * 1024


@dataclass
class ClamResult:
    infected: bool
    signature: str = ""
    error: str = ""


class ClamdClient:
    def __init__(self, host: str, port: int, timeout: float = 120.0):
        self.host, self.port, self.timeout = host, port, timeout

    async def _open(self):
        return await asyncio.wait_for(asyncio.open_connection(self.host, self.port), self.timeout)

    async def ping(self, timeout: float = 3.0) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout)
            writer.write(b"zPING\0")
            await writer.drain()
            reply = await asyncio.wait_for(reader.read(64), timeout)
            writer.close()
            return reply.strip(b"\0\n ") == b"PONG"
        except (OSError, asyncio.TimeoutError):
            return False

    async def version(self) -> str:
        """e.g. "ClamAV 1.4.3/27780/Tue Sep 29 08:26:02 2026" (engine/signature version/signature date)."""
        reader, writer = await self._open()
        try:
            writer.write(b"zVERSION\0")
            await writer.drain()
            return (await asyncio.wait_for(reader.read(256), self.timeout)).decode(errors="replace").strip("\0\n ")
        finally:
            writer.close()

    async def scan_file(self, path: str) -> ClamResult:
        try:
            return await asyncio.wait_for(self._instream(path), self.timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            return ClamResult(False, error=f"clamd unavailable: {exc!r}")

    async def _instream(self, path: str) -> ClamResult:
        reader, writer = await self._open()
        try:
            writer.write(b"zINSTREAM\0")
            with open(path, "rb") as fh:
                while chunk := fh.read(CHUNK):
                    writer.write(struct.pack("!L", len(chunk)) + chunk)
                    await writer.drain()
            writer.write(struct.pack("!L", 0))
            await writer.drain()
            reply = (await reader.read(4096)).decode(errors="replace").strip("\0\n ")
        finally:
            writer.close()
        return parse_reply(reply)


def parse_reply(reply: str) -> ClamResult:
    # "stream: OK" | "stream: Eicar-Signature FOUND" | "INSTREAM size limit exceeded. ERROR"
    if reply.endswith("FOUND"):
        sig = reply.split(":", 1)[-1].rsplit(" ", 1)[0].strip()
        return ClamResult(True, signature=sig)
    if reply.endswith("OK"):
        return ClamResult(False)
    return ClamResult(False, error=reply or "empty reply from clamd")
