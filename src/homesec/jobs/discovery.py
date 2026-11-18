"""Job: find devices on the LAN, keep the inventory, alert on unknown MACs.

Discovery order (``method: auto``):

1. ARP sweep through async-vuln-scanner's Scapy integration
   (``vulnscan.discovery``). Finds everything that answers ARP, but needs
   Scapy plus CAP_NET_RAW (Linux) or Npcap + Administrator (Windows).
2. Fallback: the OS neighbour table (``ip neigh`` / ``/proc/net/arp`` /
   ``arp -a``). Passive and unprivileged, but only lists devices this host
   recently talked to.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from vulnscan.discovery import DiscoveredHost, DiscoveryUnavailable, arp_discover_async

from homesec.config import DiscoveryConfig
from homesec.influx import MetricsWriter, Point
from homesec.inventory import Device, Inventory, Sighting
from homesec.neighbours import Neighbour, filter_networks, read_neighbour_table
from homesec.notify import Notifier
from homesec.oui import VendorLookup

log = logging.getLogger(__name__)

ArpFunc = Callable[[str, float, str | None], Awaitable[list[DiscoveredHost]]]
NeighbourFunc = Callable[[], Awaitable[list[Neighbour]]]


@dataclass
class DiscoveryResult:
    method: str
    sightings: list[Sighting] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


async def discover(
    cfg: DiscoveryConfig,
    vendors: VendorLookup,
    *,
    arp: ArpFunc = arp_discover_async,
    neighbours: NeighbourFunc = read_neighbour_table,
) -> DiscoveryResult:
    result = DiscoveryResult(method=cfg.method)
    if cfg.method in ("auto", "arp"):
        try:
            found: dict[str, DiscoveredHost] = {}
            for network in cfg.networks:
                for host in await arp(network, cfg.arp_timeout, cfg.iface):
                    found[host.mac.lower() + host.address] = host
            result.method = "arp"
            result.sightings = [
                Sighting(h.address, h.mac, vendors.vendor(h.mac), "arp") for h in found.values()
            ]
            return result
        except DiscoveryUnavailable as exc:
            if cfg.method == "arp":
                raise
            result.warnings.append(f"ARP sweep unavailable, using the neighbour table: {exc}")
            log.info("ARP sweep unavailable (%s); falling back to the neighbour table", exc)

    table = filter_networks(await neighbours(), cfg.networks)
    result.method = "neighbours"
    result.sightings = [Sighting(n.ip, n.mac, vendors.vendor(n.mac), "neighbours") for n in table]
    return result


def _describe(d: Device) -> str:
    return f"{d.mac} at {d.ip} (vendor: {d.vendor})"


class DiscoveryJob:
    name = "discovery"

    def __init__(
        self,
        cfg: DiscoveryConfig,
        inventory: Inventory,
        notifier: Notifier,
        metrics: MetricsWriter,
        *,
        vendors: VendorLookup | None = None,
        arp: ArpFunc = arp_discover_async,
        neighbours: NeighbourFunc = read_neighbour_table,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.cfg = cfg
        self.inventory = inventory
        self.notifier = notifier
        self.metrics = metrics
        self.vendors = vendors or VendorLookup(cfg.oui_file)
        self._arp = arp
        self._neighbours = neighbours
        self._clock = clock

    @property
    def interval(self) -> float:
        return self.cfg.interval

    async def run(self) -> dict:
        now = self._clock()
        first_run = self.inventory.is_empty()
        result = await discover(self.cfg, self.vendors, arp=self._arp, neighbours=self._neighbours)
        new = self.inventory.record(result.sightings, now=now)
        log.info(
            "discovery (%s): %d device(s) seen, %d new",
            result.method,
            len(result.sightings),
            len(new),
        )

        notified: list[Device] = []
        if first_run and new and self.cfg.baseline_first_run:
            # Everything is "new" on day one; one summary beats 30 alerts.
            self.inventory.mark_notified(d.mac for d in new)
            await self.notifier.send(
                f"Device inventory initialised with {len(new)} device(s)",
                [
                    *(_describe(d) for d in new[:40]),
                    "Mark yours as known: homesec devices known <MAC> --label <name>",
                ],
            )
        elif self.cfg.notify_unknown:
            pending = self.inventory.unnotified_unknown()
            if pending:
                ok = await self.notifier.send(
                    f"{len(pending)} unknown device(s) joined the network",
                    [
                        *(_describe(d) for d in pending),
                        "If it is yours: homesec devices known <MAC> --label <name>",
                    ],
                )
                if ok:  # otherwise retry on the next run
                    self.inventory.mark_notified(d.mac for d in pending)
                    notified = pending

        counts = self.inventory.counts(online_since=now - self.cfg.interval * 1.5)
        points = [
            Point(
                "homesec_devices",
                {"method": result.method},
                {**counts, "seen": len(result.sightings), "new": len(new)},
                int(now),
            )
        ]
        points += [
            Point(
                "homesec_new_device",
                {"mac": d.mac, "vendor": d.vendor},
                {"ip": d.ip, "value": 1},
                int(now),
            )
            for d in new
        ]
        for s in result.sightings:
            dev = self.inventory.get(s.mac)
            points.append(
                Point(
                    "homesec_device",
                    {"mac": dev.mac, "name": dev.name, "known": str(dev.known).lower()},
                    {"ip": dev.ip, "online": 1},
                    int(now),
                )
            )
        await self.metrics.write(points)
        return {
            "method": result.method,
            "seen": len(result.sightings),
            "new": [d.mac for d in new],
            "notified": [d.mac for d in notified],
            "warnings": result.warnings,
            **counts,
        }
