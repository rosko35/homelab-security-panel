"""Shared test helpers. Network tests only ever use servers on 127.0.0.1."""

from __future__ import annotations

from pathlib import Path

import pytest

from homesec.influx import Point
from homesec.inventory import Inventory

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).resolve().parent / "data"
SIBLINGS = ROOT.parent


class FakeNotifier:
    name = "fake"

    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.messages: list[tuple[str, list[str]]] = []

    async def send(self, title: str, lines: list[str]) -> bool:
        self.messages.append((title, list(lines)))
        return self.ok

    async def aclose(self) -> None:
        return None


class RecordingWriter:
    def __init__(self) -> None:
        self.points: list[Point] = []

    async def write(self, points: list[Point]) -> bool:
        for p in points:
            p.to_line()  # must serialise
        self.points.extend(points)
        return True

    async def aclose(self) -> None:
        return None

    def named(self, measurement: str) -> list[Point]:
        return [p for p in self.points if p.measurement == measurement]


@pytest.fixture
def inventory(tmp_path) -> Inventory:
    inv = Inventory(tmp_path / "state" / "homesec.db")
    yield inv
    inv.close()


@pytest.fixture
def notifier() -> FakeNotifier:
    return FakeNotifier()


@pytest.fixture
def metrics() -> RecordingWriter:
    return RecordingWriter()
