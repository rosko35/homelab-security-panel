"""The exporter against a database created by mini-siem's own storage code."""

import asyncio
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from minisiem.models import Alert, Event, EventType, Severity
from minisiem.storage import SQLiteStorage

from homesec.config import SiemExportConfig
from homesec.jobs.siem_export import SiemExportJob, collect, connect_readonly

NOW = datetime(2026, 11, 18, 12, 30, tzinfo=UTC)


def make_siem_db(path):
    storage = SQLiteStorage(path)
    t = NOW - timedelta(minutes=20)  # 12:10
    events = [
        Event(t, "auth", EventType.SSH_FAILED, src_ip="203.0.113.9", user="root",
              fields={"invalid_user": False}),
        Event(t, "auth", EventType.SSH_FAILED, src_ip="203.0.113.9", user="admin",
              fields={"invalid_user": True}),
        Event(t, "auth", EventType.SSH_INVALID_USER, src_ip="203.0.113.9", user="admin"),
        Event(t, "auth", EventType.SSH_ACCEPTED, src_ip="192.168.1.10", user="emre"),
        Event(NOW - timedelta(hours=3), "nginx", EventType.HTTP_REQUEST, src_ip="198.51.100.7",
              fields={"status": 404, "path": "/wp-login.php"}),
        Event(NOW - timedelta(days=5), "auth", EventType.SSH_FAILED, src_ip="203.0.113.1",
              user="pi"),
    ]  # fmt: skip
    storage.add_events(events)
    alerts = [
        Alert(t, "ssh-bruteforce", "SSH brute force", Severity.HIGH, "203.0.113.9", "m1", count=5),
        Alert(t + timedelta(minutes=5), "ssh-bruteforce", "SSH brute force", Severity.HIGH,
              "203.0.113.9", "m2", count=7),
        Alert(NOW - timedelta(hours=2), "router-admin-login", "Router shell login",
              Severity.MEDIUM, "192.168.1.10", "m3"),
        Alert(NOW - timedelta(days=4), "ssh-root-login", "Root login", Severity.CRITICAL,
              "192.168.1.10", "old"),
    ]  # fmt: skip
    for alert in alerts:
        storage.add_alert(alert)
    storage.commit()
    storage.close()


@pytest.fixture
def siem_db(tmp_path):
    path = tmp_path / "siem" / "siem.db"
    make_siem_db(path)
    return path


def test_collect_hourly_alerts_events_and_summary(siem_db):
    conn = connect_readonly(siem_db)
    try:
        points = collect(conn, NOW.timestamp(), lookback_hours=48)
    finally:
        conn.close()

    alerts = [p for p in points if p.measurement == "siem_alerts"]
    noon = int(datetime(2026, 11, 18, 12, tzinfo=UTC).timestamp())
    ten = int(datetime(2026, 11, 18, 10, tzinfo=UTC).timestamp())
    by_key = {(p.tags["rule_id"], p.time): p for p in alerts}
    assert set(by_key) == {
        ("ssh-bruteforce", noon),
        ("router-admin-login", ten),
    }  # 4-day-old one is outside
    brute = by_key[("ssh-bruteforce", noon)]
    assert brute.fields == {"alerts": 2, "events": 12}
    assert brute.tags["severity"] == "high"
    assert brute.tags["rule_name"] == "SSH brute force"

    events = {(p.tags["type"], p.time): p.fields for p in points if p.measurement == "siem_events"}
    assert events[("ssh_failed", noon)] == {"count": 2, "suspicious": 2}
    assert events[("ssh_accepted", noon)] == {"count": 1, "suspicious": 0}

    summary = next(p for p in points if p.measurement == "siem_summary").fields
    assert summary["events_24h"] == 5
    assert summary["alerts_24h"] == 3
    # mini-siem counts "Failed password for invalid user" + "Invalid user" as ONE attempt
    assert summary["ssh_attempts_24h"] == 2
    assert summary["attacker_ips_24h"] == 2  # 203.0.113.9 (ssh) + 198.51.100.7 (404 probe)
    assert summary["high_alerts_24h"] == 2
    assert summary["last_event_age_s"] == 20 * 60


def test_connection_is_read_only(siem_db):
    conn = connect_readonly(siem_db)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM alerts")
    finally:
        conn.close()


def test_job_writes_points_and_survives_missing_db(tmp_path, siem_db, metrics):
    job = SiemExportJob(
        SiemExportConfig(database=str(siem_db)), metrics, clock=lambda: NOW.timestamp()
    )
    assert asyncio.run(job.run())["exported"] == len(metrics.points) > 0

    missing = SiemExportJob(SiemExportConfig(database=str(tmp_path / "nope.db")), metrics)
    assert "not found" in asyncio.run(missing.run())["skipped"]


def test_not_a_siem_database(tmp_path, metrics):
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("CREATE TABLE x (y)").connection.commit()
    job = SiemExportJob(SiemExportConfig(database=str(other)), metrics)
    assert "does not look like a mini-siem database" in asyncio.run(job.run())["skipped"]


def test_reexport_is_idempotent(siem_db, metrics):
    job = SiemExportJob(
        SiemExportConfig(database=str(siem_db)), metrics, clock=lambda: NOW.timestamp()
    )
    asyncio.run(job.run())
    first = [(p.measurement, tuple(sorted(p.tags.items())), p.time) for p in metrics.points]
    metrics.points.clear()
    asyncio.run(job.run())
    second = [(p.measurement, tuple(sorted(p.tags.items())), p.time) for p in metrics.points]
    # Same series and timestamps -> InfluxDB overwrites instead of double counting.
    assert first == second
