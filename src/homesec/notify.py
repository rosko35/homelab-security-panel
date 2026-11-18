"""Notifications: Telegram when configured, the console otherwise.

The bot token is only read from the environment and never logged (the
Telegram API puts it in the URL path, so httpx's request logging is muted).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from collections.abc import Mapping
from typing import Protocol

import httpx

log = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org"
MAX_MESSAGE = 4096  # Telegram limit for one text message


class Notifier(Protocol):
    name: str

    async def send(self, title: str, lines: list[str]) -> bool: ...

    async def aclose(self) -> None: ...


def format_message(title: str, lines: list[str], hostname: str | None = None) -> str:
    head = f"[{hostname}] {title}" if hostname else title
    return "\n".join([head, *(f"- {line}" for line in lines)])


def split_message(text: str, limit: int = MAX_MESSAGE) -> list[str]:
    """Split on line boundaries so no chunk exceeds ``limit`` characters."""
    chunks: list[str] = []
    current = ""
    for line in text.split("\n"):
        while len(line) > limit:  # a single absurdly long line
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:limit])
            line = line[limit:]
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


class ConsoleNotifier:
    name = "console"

    def __init__(self, hostname: str | None = None) -> None:
        self.hostname = hostname

    async def send(self, title: str, lines: list[str]) -> bool:
        log.warning("%s", format_message(title, lines, self.hostname))
        return True

    async def aclose(self) -> None:
        return None


class TelegramNotifier:
    name = "telegram"

    def __init__(
        self,
        token: str,
        chat_id: str,
        *,
        hostname: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 15.0,
        max_retries: int = 2,
    ) -> None:
        # httpx logs every request URL at INFO, and this URL contains the token.
        for name in ("httpx", "httpcore"):
            logger = logging.getLogger(name)
            if logger.level < logging.WARNING:  # NOTSET (0) included
                logger.setLevel(logging.WARNING)
        self._url = f"{TELEGRAM_API}/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.hostname = hostname
        self.max_retries = max_retries
        self._http = httpx.AsyncClient(timeout=timeout, transport=transport)

    async def _post(self, text: str) -> bool:
        payload = {"chat_id": self.chat_id, "text": text, "disable_web_page_preview": True}
        for attempt in range(self.max_retries + 1):
            try:
                resp = await self._http.post(self._url, json=payload)
            except httpx.HTTPError as exc:
                # str(exc) can contain the URL, and with it the token: log the type only.
                log.warning("telegram: request failed (%s)", type(exc).__name__)
                return False
            if resp.status_code == 429 and attempt < self.max_retries:
                try:
                    wait = float(resp.json().get("parameters", {}).get("retry_after", 1))
                except ValueError:
                    wait = 1.0
                await asyncio.sleep(min(wait, 30.0))
                continue
            if resp.is_success:
                return True
            log.warning("telegram: HTTP %d from sendMessage", resp.status_code)
            return False
        return False

    async def send(self, title: str, lines: list[str]) -> bool:
        ok = True
        for chunk in split_message(format_message(title, lines, self.hostname)):
            ok = await self._post(chunk) and ok
        return ok

    async def aclose(self) -> None:
        await self._http.aclose()


def build_notifier(
    env: Mapping[str, str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Notifier:
    env = os.environ if env is None else env
    hostname = env.get("HOMESEC_HOSTNAME") or socket.gethostname()
    token = (env.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (env.get("TELEGRAM_CHAT_ID") or "").strip()
    if token and chat_id:
        return TelegramNotifier(token, chat_id, hostname=hostname, transport=transport)
    if token or chat_id:
        log.warning("only one of TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID is set; using console")
    return ConsoleNotifier(hostname)
