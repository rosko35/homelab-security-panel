"""Device inventory and job state, stored in one SQLite file.

The MAC address is the identity of a device: IP addresses change with DHCP,
MACs (mostly) do not. Phones with "private Wi-Fi address" enabled are the
exception and show up as a new, randomized MAC per network (see README).
"""

from __future__ import annotations

import ipaddress
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from homesec.oui import normalize_mac

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    vendor      TEXT NOT NULL DEFAULT 'unknown',
    label       TEXT,
    known       INTEGER NOT NULL DEFAULT 0,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    notified    INTEGER NOT NULL DEFAULT 0,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    started     REAL NOT NULL,
    finished    REAL NOT NULL,
    report_path TEXT NOT NULL,
    hosts       INTEGER NOT NULL,
    open_ports  INTEGER NOT NULL,
    changes     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS job_runs (
    name        TEXT PRIMARY KEY,
    last_run    REAL NOT NULL,
    status      TEXT NOT NULL,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class Sighting:
    ip: str
    mac: str
    vendor: str = "unknown"
    source: str = "arp"


@dataclass(frozen=True)
class Device:
    mac: str
    ip: str
    vendor: str
    label: str | None
    known: bool
    first_seen: float
    last_seen: float
    notified: bool
    source: str | None = None

    @property
    def name(self) -> str:
        """Short display name: label, else vendor, else the MAC."""
        if self.label:
            return self.label
        return self.vendor if self.vendor not in ("unknown", "") else self.mac


@dataclass(frozen=True)
class ScanRecord:
    id: int
    started: float
    finished: float
    report_path: str
    hosts: int
    open_ports: int
    changes: int


class DeviceNotFound(LookupError):
    pass


class Inventory:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # Two containers (discovery + scanner) share this file; WAL lets them coexist.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(_SCHEMA)
        self.conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Inventory:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- devices -----------------------------------------------------------
    @staticmethod
    def _device(row: sqlite3.Row) -> Device:
        return Device(
            mac=row["mac"],
            ip=row["ip"],
            vendor=row["vendor"],
            label=row["label"],
            known=bool(row["known"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            notified=bool(row["notified"]),
            source=row["source"],
        )

    def is_empty(self) -> bool:
        return self.conn.execute("SELECT 1 FROM devices LIMIT 1").fetchone() is None

    def record(self, sightings: Iterable[Sighting], now: float | None = None) -> list[Device]:
        """Upsert sightings; return the devices whose MAC was never seen before."""
        now = time.time() if now is None else now
        new: list[str] = []
        with self.conn:
            for s in sightings:
                mac = normalize_mac(s.mac)
                if mac is None:
                    continue
                cur = self.conn.execute(
                    "UPDATE devices SET ip = ?, last_seen = MAX(last_seen, ?), source = ?,"
                    " vendor = CASE WHEN vendor = 'unknown' THEN ? ELSE vendor END"
                    " WHERE mac = ?",
                    (s.ip, now, s.source, s.vendor, mac),
                )
                if cur.rowcount == 0:
                    self.conn.execute(
                        "INSERT INTO devices (mac, ip, vendor, first_seen, last_seen, source)"
                        " VALUES (?,?,?,?,?,?)",
                        (mac, s.ip, s.vendor or "unknown", now, now, s.source),
                    )
                    new.append(mac)
        return [self.get(m) for m in new]

    def unnotified_unknown(self) -> list[Device]:
        rows = self.conn.execute(
            "SELECT * FROM devices WHERE known = 0 AND notified = 0 ORDER BY first_seen, mac"
        ).fetchall()
        return [self._device(r) for r in rows]

    def mark_notified(self, macs: Iterable[str]) -> None:
        with self.conn:
            self.conn.executemany(
                "UPDATE devices SET notified = 1 WHERE mac = ?", [(m,) for m in macs]
            )

    def resolve(self, ref: str) -> str:
        """Accept a MAC in any notation, or the device's current IP address."""
        mac = normalize_mac(ref)
        if mac is not None:
            if self.conn.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone():
                return mac
            raise DeviceNotFound(f"no device with MAC {mac}")
        try:
            ip = str(ipaddress.ip_address(ref.strip()))
        except ValueError as exc:
            raise DeviceNotFound(f"{ref!r} is neither a MAC nor an IP address") from exc
        rows = self.conn.execute(
            "SELECT mac FROM devices WHERE ip = ? ORDER BY last_seen DESC", (ip,)
        ).fetchall()
        if not rows:
            raise DeviceNotFound(f"no device currently at {ip}")
        return rows[0]["mac"]

    def get(self, ref: str) -> Device:
        mac = self.resolve(ref)
        row = self.conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return self._device(row)

    def set_known(self, ref: str, known: bool = True, label: str | None = None) -> Device:
        mac = self.resolve(ref)
        with self.conn:
            self.conn.execute(
                "UPDATE devices SET known = ?, label = COALESCE(?, label),"
                " notified = CASE WHEN ? THEN 1 ELSE notified END WHERE mac = ?",
                (int(known), label, int(known), mac),
            )
        return self.get(mac)

    def set_label(self, ref: str, label: str | None) -> Device:
        mac = self.resolve(ref)
        with self.conn:
            self.conn.execute("UPDATE devices SET label = ? WHERE mac = ?", (label or None, mac))
        return self.get(mac)

    def forget(self, ref: str) -> None:
        mac = self.resolve(ref)
        with self.conn:
            self.conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))

    def devices(
        self, *, unknown_only: bool = False, seen_since: float | None = None
    ) -> list[Device]:
        sql = "SELECT * FROM devices WHERE 1 = 1"
        params: list = []
        if unknown_only:
            sql += " AND known = 0"
        if seen_since is not None:
            sql += " AND last_seen >= ?"
            params.append(seen_since)
        rows = self.conn.execute(sql, params).fetchall()
        devices = [self._device(r) for r in rows]
        return sorted(devices, key=lambda d: (ipaddress.ip_address(d.ip), d.mac))

    def counts(self, online_since: float) -> dict[str, int]:
        row = self.conn.execute(
            "SELECT COUNT(*) AS total, COALESCE(SUM(known), 0) AS known,"
            " COALESCE(SUM(CASE WHEN last_seen >= ? THEN 1 ELSE 0 END), 0) AS online"
            " FROM devices",
            (online_since,),
        ).fetchone()
        return {
            "total": row["total"],
            "known": row["known"],
            "unknown": row["total"] - row["known"],
            "online": row["online"],
        }

    # -- scans -------------------------------------------------------------
    def add_scan(
        self,
        *,
        started: float,
        finished: float,
        report_path: str,
        hosts: int,
        open_ports: int,
        changes: int,
    ) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO scans (started, finished, report_path, hosts, open_ports, changes)"
                " VALUES (?,?,?,?,?,?)",
                (started, finished, report_path, hosts, open_ports, changes),
            )
        return int(cur.lastrowid or 0)

    def scans(self, limit: int | None = None) -> list[ScanRecord]:
        sql = "SELECT * FROM scans ORDER BY started DESC, id DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [ScanRecord(**dict(r)) for r in self.conn.execute(sql).fetchall()]

    def delete_scan(self, scan_id: int) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    # -- job bookkeeping ---------------------------------------------------
    def last_run(self, job: str) -> float | None:
        row = self.conn.execute("SELECT last_run FROM job_runs WHERE name = ?", (job,)).fetchone()
        return row["last_run"] if row else None

    def set_last_run(self, job: str, when: float, status: str, error: str | None = None) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO job_runs (name, last_run, status, error) VALUES (?,?,?,?)"
                " ON CONFLICT(name) DO UPDATE SET last_run = excluded.last_run,"
                " status = excluded.status, error = excluded.error",
                (job, when, status, error),
            )

    def job_runs(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM job_runs ORDER BY name")]
