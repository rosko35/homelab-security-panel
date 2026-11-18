import pytest

from homesec.neighbours import (
    Neighbour,
    filter_networks,
    parse_arp_a,
    parse_ip_neigh,
    parse_proc_net_arp,
)
from homesec.oui import VendorLookup, is_locally_administered, normalize_mac

from conftest import DATA


def pairs(neighbours):
    return [(n.ip, n.mac) for n in neighbours]


def test_ip_neigh_skips_failed_incomplete_and_ipv6():
    result = parse_ip_neigh((DATA / "ip_neigh.txt").read_text())
    assert pairs(result) == [
        ("192.168.1.1", "3c:a6:2f:12:34:56"),
        ("192.168.1.23", "b8:27:eb:aa:bb:cc"),
        ("192.168.1.40", "24:0a:c4:01:02:03"),
        ("192.168.1.90", "9a:1b:2c:3d:4e:5f"),
        ("172.17.0.2", "02:42:ac:11:00:02"),
    ]
    assert result[0].iface == "eth0"
    assert result[3].iface == "wlan0"


def test_proc_net_arp_requires_complete_flag():
    result = parse_proc_net_arp((DATA / "proc_net_arp.txt").read_text())
    assert pairs(result) == [
        ("192.168.1.1", "3c:a6:2f:12:34:56"),
        ("192.168.1.23", "b8:27:eb:aa:bb:cc"),
        ("192.168.1.90", "9a:1b:2c:3d:4e:5f"),
    ]


@pytest.mark.parametrize("crlf", [False, True])
def test_windows_arp_a(crlf):
    text = (DATA / "arp_windows.txt").read_text()
    if crlf:
        text = text.replace("\n", "\r\n")
    result = parse_arp_a(text)
    # broadcast (ff-ff..) and multicast (01-00-5e..) entries are dropped
    assert pairs(result) == [
        ("192.168.1.1", "3c:a6:2f:12:34:56"),
        ("192.168.1.23", "b8:27:eb:aa:bb:cc"),
        ("172.25.50.7", "00:15:5d:01:02:03"),
    ]
    assert result[0].iface == "192.168.1.10"
    assert result[2].iface == "172.25.48.1"


def test_windows_arp_a_with_localised_headers():
    text = (
        "Arabirim: 192.168.1.10 --- 0x12\n"
        "  Internet Adresi       Fiziksel Adres        Tür\n"
        "  192.168.1.1           3c-a6-2f-12-34-56     dinamik\n"
    )
    assert pairs(parse_arp_a(text)) == [("192.168.1.1", "3c:a6:2f:12:34:56")]


def test_macos_arp_a_pads_short_octets_and_skips_incomplete():
    result = parse_arp_a((DATA / "arp_macos.txt").read_text())
    assert pairs(result) == [
        ("192.168.1.1", "3c:a6:2f:12:34:56"),
        ("192.168.1.23", "b8:27:eb:aa:bb:cc"),
        ("192.168.1.40", "24:0a:c4:01:02:03"),
    ]
    assert result[0].iface == "en0"


def test_linux_net_tools_arp_a():
    result = parse_arp_a((DATA / "arp_nettools.txt").read_text())
    assert pairs(result) == [
        ("192.168.1.1", "3c:a6:2f:12:34:56"),
        ("192.168.1.23", "b8:27:eb:aa:bb:cc"),
    ]
    assert result[1].iface == "eth0"


def test_filter_networks_and_dedupe():
    items = [
        Neighbour("192.168.1.9", "aa:aa:aa:aa:aa:01"),
        Neighbour("192.168.1.2", "aa:aa:aa:aa:aa:02"),
        Neighbour("192.168.1.2", "aa:aa:aa:aa:aa:02", "eth1"),
        Neighbour("10.0.0.5", "aa:aa:aa:aa:aa:03"),
    ]
    assert pairs(filter_networks(items, ["192.168.1.0/24"])) == [
        ("192.168.1.2", "aa:aa:aa:aa:aa:02"),
        ("192.168.1.9", "aa:aa:aa:aa:aa:01"),
    ]
    assert len(filter_networks(items, [])) == 3


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
        ("0:11:22:3:4:5", "00:11:22:03:04:05"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("AABBCCDDEEFF", "aa:bb:cc:dd:ee:ff"),
        ("not-a-mac", None),
        ("192.168.1.1", None),
    ],
)
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


def test_vendor_lookup(tmp_path):
    vendors = VendorLookup()
    assert vendors.vendor("b8:27:eb:00:00:01") == "Raspberry Pi Foundation"
    assert vendors.vendor("24-0A-C4-00-00-01") == "Espressif"
    assert vendors.vendor("00:00:01:00:00:01") == "unknown"
    # locally administered bit -> randomized private address (phones, VMs)
    assert is_locally_administered("9a:1b:2c:3d:4e:5f")
    assert vendors.vendor("9a:1b:2c:3d:4e:5f") == "randomized (private address)"

    ieee = tmp_path / "oui.csv"
    ieee.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,000001,"Example Corp",Somewhere\n',
        encoding="utf-8",
    )
    assert VendorLookup(ieee).vendor("00:00:01:12:34:56") == "Example Corp"
