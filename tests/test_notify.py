import asyncio
import json
import logging

import httpx

from homesec.notify import (
    MAX_MESSAGE,
    ConsoleNotifier,
    TelegramNotifier,
    build_notifier,
    split_message,
)

TOKEN = "123456:TEST-TOKEN-not-real"


class FakeTelegram:
    def __init__(self, statuses=None):
        self.requests: list[httpx.Request] = []
        self.statuses = list(statuses or [])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status = self.statuses.pop(0) if self.statuses else 200
        if status == 429:
            return httpx.Response(429, json={"ok": False, "parameters": {"retry_after": 0}})
        return httpx.Response(status, json={"ok": status == 200})

    @property
    def transport(self):
        return httpx.MockTransport(self.handler)

    def payloads(self):
        return [json.loads(r.content) for r in self.requests]


def test_telegram_sends_message(caplog):
    fake = FakeTelegram()
    notifier = TelegramNotifier(TOKEN, "42", hostname="pi", transport=fake.transport)

    async def go():
        try:
            return await notifier.send("New device", ["aa:bb at 192.168.1.5"])
        finally:
            await notifier.aclose()

    with caplog.at_level(logging.DEBUG):
        assert asyncio.run(go()) is True
    req = fake.requests[0]
    assert req.method == "POST"
    assert req.url.path == f"/bot{TOKEN}/sendMessage"
    assert fake.payloads()[0] == {
        "chat_id": "42",
        "text": "[pi] New device\n- aa:bb at 192.168.1.5",
        "disable_web_page_preview": True,
    }
    assert TOKEN not in caplog.text


def test_telegram_retries_on_429_and_reports_errors(caplog):
    fake = FakeTelegram(statuses=[429, 200, 500])
    notifier = TelegramNotifier(TOKEN, "42", transport=fake.transport)

    async def go():
        try:
            first = await notifier.send("a", ["b"])
            second = await notifier.send("c", ["d"])
            return first, second
        finally:
            await notifier.aclose()

    with caplog.at_level(logging.WARNING):
        assert asyncio.run(go()) == (True, False)
    assert len(fake.requests) == 3
    assert "HTTP 500" in caplog.text
    assert TOKEN not in caplog.text


def test_telegram_network_error_does_not_raise_or_leak_token(caplog):
    def boom(request):
        raise httpx.ConnectError(f"cannot reach {request.url}")

    notifier = TelegramNotifier(TOKEN, "42", transport=httpx.MockTransport(boom))

    async def go():
        try:
            return await notifier.send("a", ["b"])
        finally:
            await notifier.aclose()

    with caplog.at_level(logging.DEBUG):
        assert asyncio.run(go()) is False
    assert TOKEN not in caplog.text


def test_long_messages_are_split_on_lines():
    fake = FakeTelegram()
    notifier = TelegramNotifier(TOKEN, "42", transport=fake.transport)
    lines = [f"line {i} " + "x" * 90 for i in range(100)]

    async def go():
        try:
            return await notifier.send("many", lines)
        finally:
            await notifier.aclose()

    assert asyncio.run(go())
    texts = [p["text"] for p in fake.payloads()]
    assert len(texts) > 1
    assert all(len(t) <= MAX_MESSAGE for t in texts)
    assert "\n".join(texts).count("line ") == 100


def test_split_message_handles_huge_single_line():
    chunks = split_message("x" * 10000, limit=4096)
    assert [len(c) for c in chunks] == [4096, 4096, 1808]


def test_build_notifier_defaults_to_console():
    assert isinstance(build_notifier({}), ConsoleNotifier)
    assert isinstance(build_notifier({"TELEGRAM_BOT_TOKEN": TOKEN}), ConsoleNotifier)
    tg = build_notifier({"TELEGRAM_BOT_TOKEN": TOKEN, "TELEGRAM_CHAT_ID": "1"})
    assert isinstance(tg, TelegramNotifier)
    asyncio.run(tg.aclose())


def test_console_notifier_logs(caplog):
    with caplog.at_level(logging.WARNING):
        assert asyncio.run(ConsoleNotifier("pi").send("t", ["x"]))
    assert "[pi] t" in caplog.text
