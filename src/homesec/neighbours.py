"""Read the operating system's neighbour (ARP) table.

This is the fallback when raw-socket ARP sweeps are not possible (no Scapy,
no root/CAP_NET_RAW, Windows without Npcap). It is *passive*: it only lists
devices this machine has recently talked to, so it finds fewer devices than
an ARP sweep. It never sends a packet.

Supported formats:

* Linux ``ip neigh show``
* Linux ``/proc/net/arp`` (works in slim containers without iproute2)
* Windows ``arp -a``
* macOS / BSD / Linux net-tools ``arp -a``
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shutil
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from homesec.oui import is_unicast, normalize_mac

log = logging.getLogger(__name__)

PROC_NET_ARP = Path("/proc/net/arp")


@dataclass(frozen=True)
class Neighbour:
    ip: str
    mac: str
    iface: str | None = None


def _valid(ip: str, mac_raw: str) -> tuple[str, str] | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4 or addr.is_multicast or addr.is_unspecified:
        return None
    mac = normalize_mac(mac_raw)
    if mac is None or mac == "00:00:00:00:00:00" or not is_unicast(mac):
        return None
    return str(addr), mac


# 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
# 192.168.1.9 dev eth0  FAILED            (no lladdr -> skipped)
_IP_NEIGH = re.compile(
    r"^(?P<ip>\S+)\s+dev\s+(?P<iface>\S+)(?:\s+lladdr\s+(?P<mac>\S+))?(?P<rest>.*)$"
)
_BAD_STATES = {"FAILED", "INCOMPLETE"}


def parse_ip_neigh(text: str) -> list[Neighbour]:
    out = []
    for line in text.splitlines():
        m = _IP_NEIGH.match(line.strip())
        if not m or not m["mac"]:
            continue
        if set(m["rest"].split()) & _BAD_STATES:
            continue
        if ok := _valid(m["ip"], m["mac"]):
            out.append(Neighbour(ok[0], ok[1], m["iface"]))
    return out


def parse_proc_net_arp(text: str) -> list[Neighbour]:
    """IP address  HW type  Flags  HW address  Mask  Device"""
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hw, flags, mac, _mask, iface = parts[:6]
        try:
            if not int(flags, 16) & 0x2:  # ATF_COM: entry is complete
                continue
        except ValueError:
            continue
        if ok := _valid(ip, mac):
            out.append(Neighbour(ok[0], ok[1], iface))
    return out


# Windows:  "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic"
_WIN = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(?P<type>\S+)"
)
_WIN_IFACE = re.compile(r"^\S.*?:\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+---")
# BSD/macOS/net-tools: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
#                      "router.lan (192.168.1.1) at 0:11:22:3:4:5 [ether] on eth0"
_BSD = re.compile(
    r"^(?P<name>\S+)\s+\((?P<ip>[\d.]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+)\b(?P<rest>.*)$"
)
_BSD_IFACE = re.compile(r"\bon\s+(?P<iface>\S+)")


def parse_arp_a(text: str) -> list[Neighbour]:
    """Parse ``arp -a`` from Windows, macOS, the BSDs or Linux net-tools.

    Header lines are ignored on purpose (Windows localises them), so only the
    shape of the entry lines matters.
    """
    out = []
    win_iface: str | None = None
    for line in text.splitlines():
        if m := _WIN_IFACE.match(line):
            win_iface = m["ip"]
            continue
        if m := _WIN.match(line):
            if ok := _valid(m["ip"], m["mac"]):
                out.append(Neighbour(ok[0], ok[1], win_iface))
            continue
        if (m := _BSD.match(line.strip())) and (ok := _valid(m["ip"], m["mac"])):
            iface = _BSD_IFACE.search(m["rest"])
            out.append(Neighbour(ok[0], ok[1], iface["iface"] if iface else None))
    return out


def filter_networks(neighbours: Iterable[Neighbour], networks: Iterable[str]) -> list[Neighbour]:
    nets = [ipaddress.ip_network(n, strict=False) for n in networks]
    seen: dict[str, Neighbour] = {}
    for n in neighbours:
        if nets and not any(ipaddress.ip_address(n.ip) in net for net in nets):
            continue
        seen.setdefault(n.mac + n.ip, n)
    return sorted(seen.values(), key=lambda n: ipaddress.ip_address(n.ip))


async def _run(*cmd: str) -> str | None:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
    except (OSError, TimeoutError) as exc:
        log.debug("%s failed: %s", cmd[0], exc)
        return None
    return stdout.decode("utf-8", errors="replace") if proc.returncode == 0 else None


async def read_neighbour_table() -> list[Neighbour]:
    """Best available source for this OS; empty list if none works."""
    if sys.platform.startswith("linux"):
        if (text := await _run("ip", "-4", "neigh", "show")) is not None:
            return parse_ip_neigh(text)
        try:
            return parse_proc_net_arp(PROC_NET_ARP.read_text(encoding="ascii", errors="replace"))
        except OSError:
            pass
    if (text := await _run("arp", "-a")) is not None:
        return parse_arp_a(text)
    log.warning("no neighbour table source available (ip, /proc/net/arp, arp)")
    return []
