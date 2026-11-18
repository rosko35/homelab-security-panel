"""Job: scheduled port scan of the inventory with async-vuln-scanner.

Each run scans the devices discovery has seen recently, stores the scanner's
own JSON report, diffs it against the previous report with the scanner's
``diff_scans`` and alerts on the change kinds listed in ``scan.alert_on``.

The scanner's diff keys hosts by IP address. On a home network DHCP moves
devices around, which would show up as "host gone" + "new host" for the same
box. Hosts are therefore re-keyed by MAC address (taken from the inventory)
before diffing, and the MAC is swapped back for a readable name afterwards.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from vulnscan.cve import NVDClient
from vulnscan.diff import Change, diff_scans
from vulnscan.engine import ScanOptions, run_scan
from vulnscan.models import SEVERITY_ORDER, ScanResult
from vulnscan.report import load_json, write_json
from vulnscan.targets import Target, parse_ports

from homesec.config import ScanConfig
from homesec.influx import MetricsWriter, Point
from homesec.inventory import Device, Inventory
from homesec.notify import Notifier
from homesec.oui import normalize_mac

log = logging.getLogger(__name__)

SEVERITIES = [s for s in SEVERITY_ORDER if s != "NONE"]


def display_name(device: Device | None, ip: str, mac: str | None = None) -> str:
    if device is not None and device.label:
        return f"{device.label} ({ip})"
    if device is not None:
        return f"{device.mac} ({ip}, {device.vendor})"
    return f"{mac} ({ip})" if mac else ip


def _rekey(scan: ScanResult, devices: dict[str, Device]) -> tuple[ScanResult, dict[str, str]]:
    """Copy of ``scan`` with each host's address replaced by its MAC (when known)."""
    copy = ScanResult.from_dict(scan.to_dict())
    names: dict[str, str] = {}
    for host in copy.hosts:
        mac = normalize_mac(host.mac) if host.mac else None
        if mac:
            names[mac] = display_name(devices.get(mac), host.address, mac)
            host.address = mac
    return copy, names


def diff_by_device(old: ScanResult, new: ScanResult, devices: dict[str, Device]) -> list[Change]:
    """The scanner's diff, but stable across DHCP address changes."""
    old_k, old_names = _rekey(old, devices)
    new_k, new_names = _rekey(new, devices)
    names = {**old_names, **new_names}
    out = []
    for change in diff_scans(old_k, new_k):
        message = change.message
        label = names.get(change.host)
        if label:
            message = message.replace(change.host, label)
        out.append(Change(change.kind, label or change.host, change.port, message))
    return out


def _unique_cves(scan: ScanResult) -> dict:
    return {c.id: c for h in scan.hosts for p in h.ports for c in p.cves}


class ScanJob:
    name = "scan"

    def __init__(
        self,
        cfg: ScanConfig,
        reports_dir: str | Path,
        inventory: Inventory,
        notifier: Notifier,
        metrics: MetricsWriter,
        *,
        nvd_client_factory: Callable[[], NVDClient] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.reports_dir = Path(reports_dir)
        self.inventory = inventory
        self.notifier = notifier
        self.metrics = metrics
        self._nvd_factory = nvd_client_factory
        self._clock = clock

    @property
    def interval(self) -> float:
        return self.cfg.interval

    def targets(self, now: float) -> list[Device]:
        excluded = {normalize_mac(x) or x.strip() for x in self.cfg.exclude}
        return [
            d
            for d in self.inventory.devices(seen_since=now - self.cfg.max_device_age)
            if d.mac not in excluded and d.ip not in excluded
        ]

    def _previous(self) -> ScanResult | None:
        for record in self.inventory.scans(limit=5):
            try:
                return load_json(record.report_path)
            except (OSError, ValueError) as exc:
                log.warning("previous report %s unusable: %s", record.report_path, exc)
        return None

    async def run(self) -> dict:
        started = self._clock()
        devices = self.targets(started)
        if not devices:
            log.info("scan: no devices seen recently, nothing to scan")
            return {"hosts": 0, "open_ports": 0, "changes": [], "alerts": []}

        ports = parse_ports(self.cfg.ports)
        options = ScanOptions(
            concurrency=self.cfg.concurrency,
            timeout=self.cfg.timeout,
            rate=self.cfg.rate,
            cve=self.cfg.cve,
            nvd_cache_dir=Path(self.cfg.nvd_cache_dir) if self.cfg.nvd_cache_dir else None,
        )
        nvd = self._nvd_factory() if (self._nvd_factory and self.cfg.cve) else None
        log.info("scan: %d device(s) x %d port(s)", len(devices), len(ports))
        try:
            result = await run_scan(
                [Target(d.ip) for d in devices],
                ports,
                options,
                target_spec=[d.ip for d in devices],
                ports_spec=self.cfg.ports,
                nvd_client=nvd,
                macs={d.ip: d.mac for d in devices},
            )
        finally:
            if nvd is not None:
                await nvd.aclose()

        previous = self._previous()
        stamp = datetime.fromtimestamp(started, UTC).strftime("%Y%m%dT%H%M%SZ")
        path = write_json(result, self.reports_dir / f"scan-{stamp}.json")

        by_mac = {d.mac: d for d in self.inventory.devices()}
        changes = diff_by_device(previous, result, by_mac) if previous else []
        alerts = [c for c in changes if c.kind in self.cfg.alert_on]
        open_ports = sum(len(h.ports) for h in result.hosts)
        finished = self._clock()

        if previous is None:
            await self.notifier.send(
                "First port scan finished (baseline)",
                [
                    f"{len(devices)} device(s) scanned, {len(result.hosts)} with open ports, "
                    f"{open_ports} open port(s) in total",
                    *(
                        f"{display_name(by_mac.get(h.mac or ''), h.address, h.mac)}: "
                        + ", ".join(str(p.port) for p in h.ports)
                        for h in result.hosts
                    ),
                ],
            )
        elif alerts:
            await self.notifier.send(
                f"Port scan found {len(alerts)} change(s)", [c.message for c in alerts]
            )

        self.inventory.add_scan(
            started=started,
            finished=finished,
            report_path=str(path),
            hosts=len(result.hosts),
            open_ports=open_ports,
            changes=len(changes),
        )
        self._prune_reports()
        await self.metrics.write(self._points(result, devices, changes, by_mac, int(finished)))
        for warning in result.warnings:
            log.warning("scanner: %s", warning)
        return {
            "report": str(path),
            "hosts": len(result.hosts),
            "open_ports": open_ports,
            "changes": [c.message for c in changes],
            "alerts": [c.message for c in alerts],
        }

    def _prune_reports(self) -> None:
        for record in self.inventory.scans()[self.cfg.keep_reports :]:
            Path(record.report_path).unlink(missing_ok=True)
            self.inventory.delete_scan(record.id)

    def _points(
        self,
        result: ScanResult,
        devices: list[Device],
        changes: list[Change],
        by_mac: dict[str, Device],
        ts: int,
    ) -> list[Point]:
        cves = _unique_cves(result)
        points = [
            Point(
                "homesec_scan",
                {},
                {
                    "hosts_scanned": len(devices),
                    "hosts_with_ports": len(result.hosts),
                    "open_ports": sum(len(h.ports) for h in result.hosts),
                    "unique_cves": len(cves),
                    "changes": len(changes),
                    "alerts": sum(1 for c in changes if c.kind in self.cfg.alert_on),
                    "duration_s": float(result.duration_s or 0.0),
                },
                ts,
            )
        ]
        by_sev = Counter((c.severity or "UNKNOWN").upper() for c in cves.values())
        for sev in [*SEVERITIES, "UNKNOWN"]:
            points.append(Point("homesec_scan_cves", {"severity": sev}, {"count": by_sev[sev]}, ts))

        scanned = {h.address: h for h in result.hosts}
        for device in devices:
            name = device.label or f"{device.vendor} {device.mac[-8:]}"
            host = scanned.get(device.ip)
            ports = host.ports if host else []
            points.append(
                Point(
                    "homesec_scan_host",
                    {"host": device.ip, "mac": device.mac, "name": name},
                    {
                        "open_ports": len(ports),
                        "cves": len({c.id for p in ports for c in p.cves}),
                    },
                    ts,
                )
            )
            for p in ports:
                svc = p.service
                points.append(
                    Point(
                        "homesec_scan_port",
                        {
                            "host": device.ip,
                            "name": name,
                            "port": str(p.port),
                            "service": (svc.name if svc and svc.name else "unknown"),
                        },
                        {
                            "product": svc.label if svc else "unknown",
                            "cves": len(p.cves),
                            "max_severity": p.max_severity or "",
                        },
                        ts,
                    )
                )
        for change in changes:
            points.append(
                Point(
                    "homesec_scan_change",
                    {
                        "kind": change.kind,
                        "host": change.host,
                        "port": str(change.port) if change.port is not None else "-",
                    },
                    {"message": change.message, "alert": change.kind in self.cfg.alert_on},
                    ts,
                )
            )
        return points
