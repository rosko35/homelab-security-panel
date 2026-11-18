"""Minimal InfluxDB 2 writer (line protocol over the HTTP API).

Deliberately tiny: the panel writes a few dozen points per job run, so a
plain ``httpx`` POST is enough and keeps the image small on a Raspberry Pi.
Write failures are logged and swallowed; metrics must never stop a job.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Protocol

import httpx

log = logging.getLogger(__name__)

FieldValue = int | float | bool | str


@dataclass
class Point:
    measurement: str
    tags: dict[str, str] = field(default_factory=dict)
    fields: dict[str, FieldValue | None] = field(default_factory=dict)
    time: int | None = None  # epoch seconds (the writer uses precision=s)

    def to_line(self) -> str:
        fields = {k: v for k, v in self.fields.items() if v is not None}
        if not fields:
            raise ValueError(f"point {self.measurement!r} has no fields")
        out = _escape(self.measurement, ", ")
        for key in sorted(self.tags):
            value = self.tags[key]
            if value is None or str(value) == "":
                continue  # InfluxDB rejects empty tag values
            out += f",{_escape(key, ',= ')}={_escape(str(value), ',= ')}"
        out += " " + ",".join(f"{_escape(k, ',= ')}={_field(v)}" for k, v in fields.items())
        if self.time is not None:
            out += f" {int(self.time)}"
        return out


def _escape(text: str, chars: str) -> str:
    text = text.replace("\\", "\\\\").replace("\n", " ").replace("\r", " ")
    for ch in chars:
        text = text.replace(ch, "\\" + ch)
    return text


def _field(value: FieldValue) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return f"{value}i"
    if isinstance(value, float):
        return repr(value)
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return '"' + text.replace("\n", " ").replace("\r", " ") + '"'


class MetricsWriter(Protocol):
    async def write(self, points: list[Point]) -> bool: ...

    async def aclose(self) -> None: ...


class NullWriter:
    """Used when no InfluxDB is configured: points are only logged at debug level."""

    async def write(self, points: list[Point]) -> bool:
        for p in points:
            log.debug("metric %s", p.to_line())
        return True

    async def aclose(self) -> None:
        return None


class InfluxWriter:
    def __init__(
        self,
        url: str,
        org: str,
        bucket: str,
        token: str | None,
        *,
        retention_s: float = 365 * 86400,
        create_bucket: bool = True,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.org = org
        self.bucket = bucket
        self.retention_s = int(retention_s)
        self.create_bucket = create_bucket
        self._bucket_ready = not create_bucket
        headers = {"Authorization": f"Token {token}"} if token else {}
        self._http = httpx.AsyncClient(
            base_url=url.rstrip("/"), headers=headers, timeout=timeout, transport=transport
        )

    async def ensure_bucket(self) -> bool:
        """Create the bucket on first use (InfluxDB's init only creates the IoT bucket)."""
        if self._bucket_ready:
            return True
        try:
            resp = await self._http.get(
                "/api/v2/buckets", params={"name": self.bucket, "org": self.org}
            )
            if resp.is_success and resp.json().get("buckets"):
                self._bucket_ready = True
                return True
            orgs = await self._http.get("/api/v2/orgs", params={"org": self.org})
            org_list = orgs.json().get("orgs", []) if orgs.is_success else []
            if not org_list:
                log.warning(
                    "influx: organisation %r not found (HTTP %d)", self.org, orgs.status_code
                )
                return False
            created = await self._http.post(
                "/api/v2/buckets",
                json={
                    "name": self.bucket,
                    "orgID": org_list[0]["id"],
                    "retentionRules": [{"type": "expire", "everySeconds": self.retention_s}],
                },
            )
            if created.is_success or created.status_code == 422:  # 422: already exists (race)
                log.info("influx: created bucket %r", self.bucket)
                self._bucket_ready = True
                return True
            log.warning(
                "influx: cannot create bucket %r (HTTP %d)", self.bucket, created.status_code
            )
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("influx: bucket check failed: %s", type(exc).__name__)
        return False

    async def write(self, points: list[Point]) -> bool:
        if not points:
            return True
        if not await self.ensure_bucket():
            return False
        now = int(time.time())
        body = "\n".join(
            (p if p.time is not None else Point(p.measurement, p.tags, p.fields, now)).to_line()
            for p in points
        )
        try:
            resp = await self._http.post(
                "/api/v2/write",
                params={"org": self.org, "bucket": self.bucket, "precision": "s"},
                content=body.encode("utf-8"),
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )
        except httpx.HTTPError as exc:
            log.warning("influx: write failed: %s", type(exc).__name__)
            return False
        if resp.status_code != 204 and not resp.is_success:
            log.warning("influx: write rejected (HTTP %d): %s", resp.status_code, resp.text[:200])
            return False
        return True

    async def aclose(self) -> None:
        await self._http.aclose()


def build_writer(cfg, transport: httpx.AsyncBaseTransport | None = None) -> MetricsWriter:
    """``cfg`` is an :class:`homesec.config.InfluxConfig`."""
    if not cfg.url:
        return NullWriter()
    if not cfg.token:
        log.warning("INFLUX_URL is set but INFLUX_TOKEN is not; writes will be rejected")
    return InfluxWriter(
        cfg.url,
        cfg.org,
        cfg.bucket,
        cfg.token,
        retention_s=cfg.retention,
        create_bucket=cfg.create_bucket,
        timeout=cfg.timeout,
        transport=transport,
    )
