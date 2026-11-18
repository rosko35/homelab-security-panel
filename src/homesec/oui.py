"""MAC address helpers and a tiny vendor (OUI) lookup."""

from __future__ import annotations

import csv
import re
from functools import lru_cache
from importlib import resources
from pathlib import Path

UNKNOWN = "unknown"
RANDOMIZED = "randomized (private address)"

_HEX_OCTETS = re.compile(r"^[0-9a-f]{1,2}([:-][0-9a-f]{1,2}){5}$", re.IGNORECASE)
_BARE = re.compile(r"^[0-9a-f]{12}$", re.IGNORECASE)
_DOTTED = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$", re.IGNORECASE)  # Cisco style


def normalize_mac(value: str) -> str | None:
    """Return ``aa:bb:cc:dd:ee:ff`` or None if ``value`` is not a MAC address.

    Accepts ``AA-BB-..`` (Windows), ``aa:bb:..`` (Linux), ``0:11:22:3:4:5``
    (macOS drops leading zeros), ``aabb.ccdd.eeff`` and bare 12-digit hex.
    """
    text = value.strip()
    if _HEX_OCTETS.match(text):
        octets = re.split(r"[:-]", text)
    elif _BARE.match(text):
        octets = [text[i : i + 2] for i in range(0, 12, 2)]
    elif _DOTTED.match(text):
        flat = text.replace(".", "")
        octets = [flat[i : i + 2] for i in range(0, 12, 2)]
    else:
        return None
    return ":".join(o.zfill(2).lower() for o in octets)


def is_unicast(mac: str) -> bool:
    """False for broadcast and multicast addresses (lowest bit of the first octet)."""
    return not int(mac[:2], 16) & 0x01


def is_locally_administered(mac: str) -> bool:
    """Phones and laptops with "private Wi-Fi address" set this bit (and VMs often do)."""
    return bool(int(mac[:2], 16) & 0x02)


def _load_csv(lines) -> dict[str, str]:
    table: dict[str, str] = {}
    rows = csv.reader(line for line in lines if line.strip() and not line.startswith("#"))
    for row in rows:
        if len(row) < 2:
            continue
        # Bundled file: "AA:BB:CC,Vendor". IEEE oui.csv: "MA-L,AABBCC,Vendor,Address".
        if row[0] == "MA-L" and len(row) >= 3:
            prefix, vendor = row[1], row[2]
        else:
            prefix, vendor = row[0], row[1]
        key = re.sub(r"[^0-9a-fA-F]", "", prefix).lower()
        if len(key) == 6:
            table[key] = vendor.strip()
    return table


@lru_cache(maxsize=1)
def bundled_table() -> dict[str, str]:
    text = resources.files("homesec.data").joinpath("oui.csv").read_text(encoding="utf-8")
    return _load_csv(text.splitlines())


class VendorLookup:
    def __init__(self, extra_file: str | Path | None = None) -> None:
        self.table = dict(bundled_table())
        if extra_file:
            with open(extra_file, encoding="utf-8", errors="replace") as fh:
                self.table.update(_load_csv(fh))

    def vendor(self, mac: str) -> str:
        norm = normalize_mac(mac)
        if norm is None:
            return UNKNOWN
        found = self.table.get(norm.replace(":", "")[:6])
        if found:
            return found
        return RANDOMIZED if is_locally_administered(norm) else UNKNOWN
