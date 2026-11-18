import pytest

from homesec.inventory import DeviceNotFound, Inventory, Sighting


def test_record_returns_only_new_macs(inventory):
    new = inventory.record(
        [
            Sighting("192.168.1.1", "3C-A6-2F-12-34-56", "AVM"),
            Sighting("192.168.1.5", "aa:bb:cc:00:00:05"),
        ],
        now=1000,
    )
    assert [d.mac for d in new] == ["3c:a6:2f:12:34:56", "aa:bb:cc:00:00:05"]
    assert all(not d.known for d in new)

    again = inventory.record([Sighting("192.168.1.1", "3c:a6:2f:12:34:56", "AVM")], now=2000)
    assert again == []
    router = inventory.get("3c:a6:2f:12:34:56")
    assert router.first_seen == 1000
    assert router.last_seen == 2000


def test_ip_change_keeps_identity(inventory):
    inventory.record([Sighting("192.168.1.20", "aa:bb:cc:00:00:20")], now=1000)
    inventory.set_known("aa:bb:cc:00:00:20", label="nas")
    assert inventory.record([Sighting("192.168.1.99", "aa:bb:cc:00:00:20")], now=2000) == []
    dev = inventory.get("192.168.1.99")  # lookup by current IP
    assert dev.label == "nas"
    assert dev.known
    with pytest.raises(DeviceNotFound):
        inventory.get("192.168.1.20")


def test_vendor_is_filled_in_later_but_never_overwritten(inventory):
    inventory.record([Sighting("192.168.1.2", "b8:27:eb:00:00:02", "unknown")], now=1)
    inventory.record([Sighting("192.168.1.2", "b8:27:eb:00:00:02", "Raspberry Pi")], now=2)
    inventory.record([Sighting("192.168.1.2", "b8:27:eb:00:00:02", "Other")], now=3)
    assert inventory.get("b8:27:eb:00:00:02").vendor == "Raspberry Pi"


def test_unknown_notification_bookkeeping(inventory):
    inventory.record(
        [
            Sighting("192.168.1.2", "aa:00:00:00:00:02"),
            Sighting("192.168.1.3", "aa:00:00:00:00:03"),
        ],
        now=1,
    )
    inventory.set_known("aa:00:00:00:00:02")
    assert [d.mac for d in inventory.unnotified_unknown()] == ["aa:00:00:00:00:03"]
    inventory.mark_notified(["aa:00:00:00:00:03"])
    assert inventory.unnotified_unknown() == []
    # marking a device unknown again does not re-trigger an alert by itself
    inventory.set_known("aa:00:00:00:00:02", False)
    assert inventory.unnotified_unknown() == []
    assert [d.mac for d in inventory.devices(unknown_only=True)] == [
        "aa:00:00:00:00:02",
        "aa:00:00:00:00:03",
    ]


def test_label_forget_counts_and_seen_since(inventory):
    inventory.record([Sighting("192.168.1.2", "aa:00:00:00:00:02")], now=100)
    inventory.record([Sighting("192.168.1.10", "aa:00:00:00:00:10")], now=500)
    inventory.set_label("aa-00-00-00-00-02", "printer")
    assert inventory.get("aa:00:00:00:00:02").name == "printer"
    assert [d.ip for d in inventory.devices(seen_since=400)] == ["192.168.1.10"]
    assert inventory.counts(online_since=400) == {"total": 2, "known": 0, "unknown": 2, "online": 1}
    inventory.forget("192.168.1.10")
    assert [d.mac for d in inventory.devices()] == ["aa:00:00:00:00:02"]
    with pytest.raises(DeviceNotFound):
        inventory.get("not a device")


def test_devices_sorted_numerically_by_ip(inventory):
    inventory.record(
        [Sighting(f"192.168.1.{n}", f"aa:00:00:00:00:{n:02x}") for n in (100, 9, 20)], now=1
    )
    assert [d.ip for d in inventory.devices()] == ["192.168.1.9", "192.168.1.20", "192.168.1.100"]


def test_state_survives_reopen(tmp_path):
    path = tmp_path / "s.db"
    with Inventory(path) as inv:
        inv.record([Sighting("192.168.1.2", "aa:00:00:00:00:02")], now=1)
        inv.set_last_run("scan", 123.0, "ok")
    with Inventory(path) as inv:
        assert inv.last_run("scan") == 123.0
        assert inv.get("aa:00:00:00:00:02").ip == "192.168.1.2"
