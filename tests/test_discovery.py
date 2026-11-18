import asyncio

import pytest
from vulnscan.discovery import DiscoveredHost, DiscoveryUnavailable

from homesec.config import DiscoveryConfig
from homesec.jobs.discovery import DiscoveryJob, discover
from homesec.neighbours import Neighbour
from homesec.oui import VendorLookup

from conftest import FakeNotifier


class FakeLan:
    """Stands in for both the ARP sweep and the neighbour table."""

    def __init__(self, hosts, arp_available=True):
        self.hosts = list(hosts)  # (ip, mac)
        self.arp_available = arp_available
        self.arp_calls = []

    async def arp(self, network, timeout, iface):
        self.arp_calls.append(network)
        if not self.arp_available:
            raise DiscoveryUnavailable("ARP discovery needs Scapy")
        return [DiscoveredHost(ip, mac) for ip, mac in self.hosts]

    async def neighbours(self):
        return [Neighbour(ip, mac, "eth0") for ip, mac in self.hosts] + [
            Neighbour("10.9.9.9", "aa:aa:aa:aa:aa:aa", "tun0")  # outside the watched network
        ]


def cfg(**kw):
    return DiscoveryConfig(networks=["192.168.1.0/24"], **kw)


def run(coro):
    return asyncio.run(coro)


def test_arp_is_used_when_available():
    lan = FakeLan([("192.168.1.1", "3c:a6:2f:12:34:56")])
    result = run(discover(cfg(), VendorLookup(), arp=lan.arp, neighbours=lan.neighbours))
    assert result.method == "arp"
    assert lan.arp_calls == ["192.168.1.0/24"]
    assert result.sightings[0].vendor == "AVM (FRITZ!Box)"


def test_auto_falls_back_to_neighbour_table():
    lan = FakeLan([("192.168.1.1", "3c:a6:2f:12:34:56")], arp_available=False)
    result = run(discover(cfg(), VendorLookup(), arp=lan.arp, neighbours=lan.neighbours))
    assert result.method == "neighbours"
    assert [s.ip for s in result.sightings] == ["192.168.1.1"]  # 10.9.9.9 filtered out
    assert "neighbour table" in result.warnings[0]


def test_method_arp_does_not_fall_back():
    lan = FakeLan([], arp_available=False)
    with pytest.raises(DiscoveryUnavailable):
        run(discover(cfg(method="arp"), VendorLookup(), arp=lan.arp, neighbours=lan.neighbours))


def test_method_neighbours_never_touches_arp():
    lan = FakeLan([("192.168.1.1", "3c:a6:2f:12:34:56")])
    result = run(
        discover(cfg(method="neighbours"), VendorLookup(), arp=lan.arp, neighbours=lan.neighbours)
    )
    assert result.method == "neighbours"
    assert lan.arp_calls == []


def make_job(inventory, notifier, metrics, lan, **kw):
    clock = iter(range(1000, 100000, 300))
    return DiscoveryJob(
        cfg(**kw),
        inventory,
        notifier,
        metrics,
        arp=lan.arp,
        neighbours=lan.neighbours,
        clock=lambda: next(clock),
    )


def test_first_run_is_a_baseline_then_unknown_devices_alert(inventory, notifier, metrics):
    lan = FakeLan([("192.168.1.1", "3c:a6:2f:12:34:56"), ("192.168.1.23", "b8:27:eb:aa:bb:cc")])
    job = make_job(inventory, notifier, metrics, lan)

    first = run(job.run())
    assert sorted(first["new"]) == ["3c:a6:2f:12:34:56", "b8:27:eb:aa:bb:cc"]
    assert len(notifier.messages) == 1
    assert notifier.messages[0][0] == "Device inventory initialised with 2 device(s)"

    # Same devices again: silence.
    run(job.run())
    assert len(notifier.messages) == 1

    # A new, unknown MAC appears -> exactly one alert, mentioning MAC, IP and vendor.
    lan.hosts.append(("192.168.1.40", "24:0a:c4:01:02:03"))
    third = run(job.run())
    assert third["new"] == ["24:0a:c4:01:02:03"]
    assert third["notified"] == ["24:0a:c4:01:02:03"]
    title, lines = notifier.messages[-1]
    assert title == "1 unknown device(s) joined the network"
    assert "24:0a:c4:01:02:03 at 192.168.1.40 (vendor: Espressif)" in lines

    # It stays on the network: no repeat alert.
    run(job.run())
    assert len(notifier.messages) == 2

    counts = metrics.named("homesec_devices")[-1].fields
    assert counts["total"] == 3
    assert counts["unknown"] == 3
    new_points = metrics.named("homesec_new_device")
    assert {p.tags["mac"] for p in new_points} == {
        "3c:a6:2f:12:34:56",
        "b8:27:eb:aa:bb:cc",
        "24:0a:c4:01:02:03",
    }


def test_known_device_never_alerts(inventory, notifier, metrics):
    lan = FakeLan([("192.168.1.1", "3c:a6:2f:12:34:56")])
    job = make_job(inventory, notifier, metrics, lan)
    run(job.run())
    lan.hosts.append(("192.168.1.50", "aa:bb:cc:00:00:50"))
    run(job.run())
    assert notifier.messages[-1][1][0].startswith("aa:bb:cc:00:00:50")
    inventory.set_known("192.168.1.50", label="new laptop")

    # DHCP hands it another address: still the same, known device -> no alert.
    lan.hosts[-1] = ("192.168.1.77", "aa:bb:cc:00:00:50")
    before = len(notifier.messages)
    result = run(job.run())
    assert result["new"] == []
    assert len(notifier.messages) == before
    assert inventory.get("aa:bb:cc:00:00:50").ip == "192.168.1.77"

    lan.hosts.append(("192.168.1.51", "aa:bb:cc:00:00:51"))
    job.cfg.notify_unknown = False
    before = len(notifier.messages)
    run(job.run())
    assert len(notifier.messages) == before


def test_without_baseline_every_device_alerts(inventory, notifier, metrics):
    lan = FakeLan([("192.168.1.1", "3c:a6:2f:12:34:56"), ("192.168.1.2", "aa:bb:cc:00:00:02")])
    job = make_job(inventory, notifier, metrics, lan, baseline_first_run=False)
    run(job.run())
    assert notifier.messages[0][0] == "2 unknown device(s) joined the network"


def test_failed_notification_is_retried_next_run(inventory, metrics):
    lan = FakeLan([("192.168.1.1", "3c:a6:2f:12:34:56")])
    broken = FakeNotifier(ok=False)
    job = make_job(inventory, broken, metrics, lan, baseline_first_run=False)
    run(job.run())
    run(job.run())
    assert len(broken.messages) == 2  # not marked as notified while sending fails
    broken.ok = True
    run(job.run())
    run(job.run())
    assert len(broken.messages) == 3
