"""Job: export mini-siem aggregates to InfluxDB for the shared Grafana.

Reads mini-siem's SQLite database strictly read-only (``mode=ro`` URI, and
the compose file mounts the volume ``:ro`` as well) and writes hourly
buckets. Rewriting the last ``lookback_hours`` buckets on every run is
idempotent in InfluxDB (same series + timestamp = overwrite), so late alerts
and restarts never double count.

Schema used (mini-siem ``storage.py``, schema_version 1):

* ``alerts(id, ts REAL epoch, rule_id, rule_name, severity INT 1-4, key,
  src_ip, country, message, count, mitre JSON, sample)``
* ``events(id, ts REAL epoch, source, type, src_ip, user, host, country,
  suspicious INT, tags, fields JSON, raw)``
* ``meta(key, value)`` with ``schema_version``
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

from homesec.config import SiemExportConfig
from homesec.influx import MetricsWriter, Point

log = logging.getLogger(__name__)

SUPPORTED_SCHEMA = {"1"}
SEVERITY_LABELS = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# Same definition of "one SSH attempt" as mini-siem's dashboard (storage.SSH_ATTEMPT).
_SSH_ATTEMPT = (
    "(type = 'ssh_invalid_user' OR (type = 'ssh_failed'"
    " AND COALESCE(json_extract(fields, '$.invalid_user'), 0) = 0))"
)


class SiemUnavailable(RuntimeError):
    pass


def connect_readonly(path: str | Path) -> sqlite3.Connection:
    p = Path(path)
    if not p.is_file():
        raise SiemUnavailable(f"mini-siem database not found: {p}")
    conn = sqlite3.connect(p.resolve().as_uri() + "?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.Error as exc:
        conn.close()
        raise SiemUnavailable(f"{p} does not look like a mini-siem database: {exc}") from exc
    version = row["value"] if row else None
    if version not in SUPPORTED_SCHEMA:
        log.warning("mini-siem schema_version %r is untested; exporting anyway", version)
    return conn


def collect(conn: sqlite3.Connection, now: float, lookback_hours: int) -> list[Point]:
    since_hour = (int(now) // 3600 - lookback_hours + 1) * 3600
    day_ago = now - 86400
    points: list[Point] = []

    for r in conn.execute(
        "SELECT CAST(ts / 3600 AS INTEGER) * 3600 AS hour, rule_id, MAX(rule_name) AS rule_name,"
        " MAX(severity) AS severity, COUNT(*) AS alerts, COALESCE(SUM(count), 0) AS events"
        " FROM alerts WHERE ts >= ? GROUP BY hour, rule_id ORDER BY hour, rule_id",
        (since_hour,),
    ):
        points.append(
            Point(
                "siem_alerts",
                {
                    "rule_id": r["rule_id"],
                    "rule_name": r["rule_name"],
                    "severity": SEVERITY_LABELS.get(r["severity"], str(r["severity"])),
                },
                {"alerts": int(r["alerts"]), "events": int(r["events"])},
                int(r["hour"]),
            )
        )

    for r in conn.execute(
        "SELECT CAST(ts / 3600 AS INTEGER) * 3600 AS hour, type, COUNT(*) AS n,"
        " COALESCE(SUM(suspicious), 0) AS suspicious"
        " FROM events WHERE ts >= ? GROUP BY hour, type ORDER BY hour, type",
        (since_hour,),
    ):
        points.append(
            Point(
                "siem_events",
                {"type": r["type"]},
                {"count": int(r["n"]), "suspicious": int(r["suspicious"])},
                int(r["hour"]),
            )
        )

    s = conn.execute(
        "SELECT"
        " (SELECT COUNT(*) FROM events WHERE ts >= :d) AS events_24h,"
        " (SELECT COUNT(*) FROM alerts WHERE ts >= :d) AS alerts_24h,"
        f" (SELECT COUNT(*) FROM events WHERE ts >= :d AND {_SSH_ATTEMPT}) AS ssh_attempts_24h,"
        " (SELECT COUNT(DISTINCT src_ip) FROM events WHERE ts >= :d AND suspicious = 1)"
        "   AS attacker_ips_24h,"
        " (SELECT COUNT(*) FROM alerts WHERE ts >= :d AND severity >= 3) AS high_alerts_24h,"
        " (SELECT MAX(ts) FROM events) AS last_event",
        {"d": day_ago},
    ).fetchone()
    fields = {k: int(s[k]) for k in s.keys() if k != "last_event"}  # noqa: SIM118
    fields["last_event_age_s"] = int(now - s["last_event"]) if s["last_event"] else None
    points.append(Point("siem_summary", {}, fields, int(now)))
    return points


class SiemExportJob:
    name = "siem_export"

    def __init__(
        self,
        cfg: SiemExportConfig,
        metrics: MetricsWriter,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self._clock = clock

    @property
    def interval(self) -> float:
        return self.cfg.interval

    async def run(self) -> dict:
        now = self._clock()
        try:
            conn = connect_readonly(self.cfg.database)
        except SiemUnavailable as exc:
            log.warning("siem export skipped: %s", exc)
            return {"exported": 0, "skipped": str(exc)}
        try:
            points = collect(conn, now, self.cfg.lookback_hours)
        finally:
            conn.close()
        await self.metrics.write(points)
        return {"exported": len(points)}
