"""Scan job against real asyncio services on 127.0.0.1 and the scanner's real models.

The NVD API is replaced by an httpx MockTransport; nothing leaves the machine.
"""

import asyncio
from pathlib import Path

import httpx
from vulnscan.cve import NVDClient
from vulnscan.diff import NEW_HOST, PORT_CLOSED, PORT_OPENED, SERVICE_CHANGED
from vulnscan.models import HostResult, PortResult, ScanResult, Service
from vulnscan.report import load_json

from homesec.config import ScanConfig
from homesec.inventory import Sighting
from homesec.jobs.scan import ScanJob, diff_by_device

MAC = "aa:bb:cc:00:00:01"


def nvd_item(cve_id, score, severity):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"{cve_id} test entry"}],
            "metrics": {
                "cvssMetricV31": [
                    {"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": severity}}
                ]
            },
        }
    }


class FakeNVD:
    """Returns one OpenSSH CVE on the first scan and an extra one afterwards."""

    def __init__(self):
        self.scan_no = 0
        self.queries = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        match = request.url.params.get("virtualMatchString", "")
        self.queries.append(match)
        items = []
        if "openssh" in match:
            items.append(nvd_item("CVE-2023-0001", 7.5, "HIGH"))
            if self.scan_no >= 2:
                items.append(nvd_item("CVE-2024-0002", 9.8, "CRITICAL"))
        return httpx.Response(
            200, json={"totalResults": len(items), "resultsPerPage": 2000, "vulnerabilities": items}
        )

    def client(self, tmp_path):
        return NVDClient(
            use_env_key=False,
            cache_dir=tmp_path / "nvd",
            use_cache=False,
            min_interval=0,
            transport=httpx.MockTransport(self.handler),
        )


def banner_server(state: dict, key: str):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(state[key])
            await writer.drain()
            await asyncio.sleep(0.05)
        except ConnectionError:
            pass
        finally:
            writer.close()

    return handle


def test_scan_baseline_then_alerts_on_changes(tmp_path, inventory, notifier, metrics):
    inventory.record([Sighting("127.0.0.1", MAC, "unknown")], now=1)
    inventory.set_known(MAC, label="lab box")
    nvd = FakeNVD()
    state = {
        "ssh": b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
        "ftp": b"220 (vsFTPd 3.0.3)\r\n",
    }
    clock = iter(range(1_000_000, 2_000_000, 60))

    async def scenario():
        ssh = await asyncio.start_server(banner_server(state, "ssh"), "127.0.0.1", 0)
        ftp = await asyncio.start_server(banner_server(state, "ftp"), "127.0.0.1", 0)
        ssh_port = ssh.sockets[0].getsockname()[1]
        ftp_port = ftp.sockets[0].getsockname()[1]
        cfg = ScanConfig(
            ports=str(ssh_port),
            cve=True,
            concurrency=20,
            timeout=1.0,
            rate=None,
            max_device_age="3650d",
            keep_reports=2,
        )

        def factory():
            nvd.scan_no += 1
            return nvd.client(tmp_path)

        job = ScanJob(
            cfg,
            tmp_path / "reports",
            inventory,
            notifier,
            metrics,
            nvd_client_factory=factory,
            clock=lambda: float(next(clock)),
        )
        try:
            first = await job.run()
            # The owner updates the SSH server and starts an FTP server (oops).
            state["ssh"] = b"SSH-2.0-OpenSSH_9.6p1\r\n"
            cfg.ports = f"{ssh_port},{ftp_port}"
            second = await job.run()
            third = await job.run()  # nothing changed
        finally:
            for server in (ssh, ftp):
                server.close()
                await server.wait_closed()
        return ssh_port, ftp_port, first, second, third

    ssh_port, ftp_port, first, second, third = asyncio.run(scenario())

    # 1st run: baseline report, one summary message, no change alerts.
    assert first["open_ports"] == 1
    assert first["alerts"] == []
    assert notifier.messages[0][0] == "First port scan finished (baseline)"
    assert not Path(first["report"]).exists()  # pruned later (keep_reports=2)

    # 2nd run: new port, changed version, new CVE -> one Telegram message.
    alerts = second["alerts"]
    assert f"port {ftp_port}/tcp newly open on lab box (127.0.0.1) (vsftpd 3.0.3)" in alerts
    assert (
        f"service changed on lab box (127.0.0.1):{ssh_port}: OpenSSH 8.2p1 -> OpenSSH 9.6p1"
        in alerts
    )
    assert any(a.startswith(f"1 new CVE(s) for lab box (127.0.0.1):{ssh_port}") for a in alerts)
    assert any("CVE-2024-0002" in a for a in alerts)
    title, lines = notifier.messages[1]
    assert title == "Port scan found 3 change(s)"
    assert sorted(lines) == sorted(alerts)

    # 3rd run: identical -> no message.
    assert third["changes"] == []
    assert len(notifier.messages) == 2

    # Reports are kept on disk and pruned to keep_reports.
    remaining = sorted(Path(tmp_path / "reports").glob("scan-*.json"))
    assert len(remaining) == 2
    assert len(inventory.scans()) == 2
    assert Path(third["report"]) in remaining
    report = load_json(second["report"])  # the scanner's own JSON format
    assert report.hosts[0].mac == MAC
    assert {p.service.label for p in report.hosts[0].ports} == {"OpenSSH 9.6p1", "vsftpd 3.0.3"}

    # Metrics for Grafana.
    crit = [
        p
        for p in metrics.named("homesec_scan_cves")
        if p.tags["severity"] == "CRITICAL" and p.time == metrics.named("homesec_scan")[1].time
    ]
    assert crit[0].fields["count"] == 1
    hosts = metrics.named("homesec_scan_host")
    assert [p.fields["open_ports"] for p in hosts] == [1, 2, 2]
    assert hosts[0].tags == {"host": "127.0.0.1", "mac": MAC, "name": "lab box"}
    changes = metrics.named("homesec_scan_change")
    assert {p.tags["kind"] for p in changes} == {"port_opened", "service_changed", "new_cve"}
    ports = {p.tags["port"]: p for p in metrics.named("homesec_scan_port")}
    assert ports[str(ftp_port)].fields["product"] == "vsftpd 3.0.3"


def test_no_recent_devices_means_no_scan(tmp_path, inventory, notifier, metrics):
    inventory.record([Sighting("127.0.0.1", MAC)], now=1)  # seen long ago
    job = ScanJob(ScanConfig(max_device_age="1d"), tmp_path, inventory, notifier, metrics)
    assert asyncio.run(job.run())["hosts"] == 0
    assert notifier.messages == []


def test_excluded_devices_are_not_scanned(inventory):
    inventory.record(
        [Sighting("192.168.1.5", "aa:00:00:00:00:05"), Sighting("192.168.1.6", MAC)], now=10
    )
    cfg = ScanConfig(exclude=["192.168.1.5", MAC.upper()], max_device_age="1d")
    job = ScanJob(cfg, ".", inventory, None, None)
    assert job.targets(now=20) == []


def _scan(*hosts):
    return ScanResult(
        targets=[], ports_spec="top", started_at="2026-01-01T00:00:00+00:00", hosts=list(hosts)
    )


def _host(ip, mac, *ports):
    return HostResult(
        address=ip,
        mac=mac,
        ports=[
            PortResult(port=p, service=Service(name="ssh", product="OpenSSH", version="9.6p1"))
            for p in ports
        ],
    )


def test_diff_follows_devices_across_dhcp_changes(inventory):
    inventory.record([Sighting("192.168.1.20", "aa:00:00:00:00:20")], now=1)
    inventory.set_label("aa:00:00:00:00:20", "nas")
    devices = {d.mac: d for d in inventory.devices()}

    old = _scan(_host("192.168.1.20", "aa:00:00:00:00:20", 22))
    new = _scan(_host("192.168.1.99", "aa:00:00:00:00:20", 22, 445))

    # The scanner's own diff sees two different hosts ...
    from vulnscan.diff import HOST_GONE, diff_scans

    assert {c.kind for c in diff_scans(old, new)} == {NEW_HOST, HOST_GONE}
    # ... re-keyed by MAC it is one device with one new port.
    changes = diff_by_device(old, new, devices)
    assert [(c.kind, c.port) for c in changes] == [(PORT_OPENED, 445)]
    assert changes[0].message == "port 445/tcp newly open on nas (192.168.1.99) (OpenSSH 9.6p1)"
    assert changes[0].host == "nas (192.168.1.99)"


def test_diff_without_mac_falls_back_to_ip(inventory):
    old = _scan(_host("192.168.1.30", None, 22, 80))
    new = _scan(_host("192.168.1.30", None, 22))
    changes = diff_by_device(old, new, {})
    assert [(c.kind, c.host) for c in changes] == [(PORT_CLOSED, "192.168.1.30")]
    assert SERVICE_CHANGED not in {c.kind for c in changes}
