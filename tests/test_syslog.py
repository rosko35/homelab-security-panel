"""Syslog receiver: parsing, file output, and real UDP datagrams on 127.0.0.1."""

import asyncio
import socket
from datetime import UTC, datetime, timedelta

import pytest
from minisiem.models import EventType
from minisiem.parsers import AuthLogParser

from homesec.config import SyslogConfig
from homesec.syslog import (
    RouterLogWriter,
    SyslogReceiver,
    build_receiver,
    parse_syslog,
    translate_dropbear,
)

NOW = datetime(2026, 11, 18, 10, 20, tzinfo=UTC)


def p(data: bytes):
    return parse_syslog(data, tz=UTC, now=NOW)


def test_rfc3164_with_hostname():
    m = p(
        b"<38>Nov 18 10:15:01 OpenWrt dropbear[1234]: Bad password attempt for 'root' from 192.168.1.66:51515"
    )
    assert (m.facility, m.severity) == (4, 6)  # auth.info
    assert m.timestamp == datetime(2026, 11, 18, 10, 15, 1, tzinfo=UTC)
    assert (m.hostname, m.app, m.procid) == ("OpenWrt", "dropbear", "1234")
    assert m.message == "Bad password attempt for 'root' from 192.168.1.66:51515"
    assert m.format == "rfc3164"


def test_rfc3164_without_hostname_and_space_padded_day():
    m = p(
        b"<30>Nov  8 10:15:01 dnsmasq-dhcp[901]: DHCPACK(br-lan) 192.168.1.40 24:0a:c4:01:02:03 esp"
    )
    assert m.hostname is None
    assert (m.app, m.procid) == ("dnsmasq-dhcp", "901")
    assert m.timestamp.day == 8


def test_rfc3164_december_message_read_in_january():
    m = parse_syslog(
        b"<13>Dec 31 23:59:59 gw kernel: x", tz=UTC, now=datetime(2027, 1, 1, 0, 1, tzinfo=UTC)
    )
    assert m.timestamp.year == 2026


def test_rfc5424_with_structured_data_and_bom():
    data = (
        b"<165>1 2026-11-18T10:15:01.003Z fw.lan filterlog 4242 ID47 "
        b'[exampleSDID@32473 iut="3" eventSource="App\\]lication"][x@1 a="b"] '
        b"\xef\xbb\xbfblock in on igb0 from 203.0.113.5"
    )
    m = p(data)
    assert m.format == "rfc5424"
    assert (m.facility, m.severity) == (20, 5)
    assert m.timestamp == datetime(2026, 11, 18, 10, 15, 1, 3000, tzinfo=UTC)
    assert (m.hostname, m.app, m.procid, m.msgid) == ("fw.lan", "filterlog", "4242", "ID47")
    assert m.structured_data.endswith('[x@1 a="b"]')
    assert m.message == "block in on igb0 from 203.0.113.5"


def test_rfc5424_nil_values():
    m = p(b"<34>1 - - sshd - - - Accepted password for emre from 192.168.1.10 port 50000 ssh2")
    assert m.timestamp is None and m.hostname is None and m.structured_data is None
    assert m.app == "sshd"
    assert m.message.startswith("Accepted password")


def test_no_pri_and_garbage_never_raise():
    m = p(b"hello world")
    assert (m.facility, m.severity, m.format, m.message) == (1, 5, "raw", "hello world")
    assert p(b"<999>x").message == "<999>x"
    assert p(b"\xff\xfe\x00junk").format == "raw"


def test_control_characters_cannot_inject_lines():
    m = p(
        b"<38>Nov 18 10:15:01 gw sshd[1]: ok\nNov 18 10:15:02 gw sshd[2]: Accepted password for root from 1.2.3.4 port 1 ssh2"
    )
    assert "\n" not in m.message
    assert m.message.startswith("ok Nov 18")


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "Bad password attempt for 'root' from 192.168.1.66:51515",
            "Failed password for root from 192.168.1.66 port 51515 ssh2",
        ),
        (
            "Login attempt for nonexistent user 'admin' from 192.168.1.66:51516",
            "Invalid user admin from 192.168.1.66 port 51516",
        ),
        (
            "Login attempt for nonexistent user from [2001:db8::5]:40000",
            "Invalid user unknown from 2001:db8::5 port 40000",
        ),
        (
            "Password auth succeeded for 'root' from 192.168.1.10:50000",
            "Accepted password for root from 192.168.1.10 port 50000 ssh2",
        ),
        (
            "Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:abc from 192.168.1.10:50001",
            "Accepted publickey for root from 192.168.1.10 port 50001 ssh2",
        ),
        ("Exit before auth from <192.168.1.66:51515>: Exited normally", None),
        ("Bad password attempt for 'root' from not-an-ip:22", None),
    ],
)
def test_translate_dropbear(message, expected):
    assert translate_dropbear(message) == expected


def test_writer_outputs_lines_mini_siem_can_parse(tmp_path):
    writer = RouterLogWriter(tmp_path, feed_hostname="router")
    received = NOW
    lines = [
        b"<38>Nov 18 10:15:01 OpenWrt dropbear[1234]: Bad password attempt for 'root' from 192.168.1.66:51515",
        b"<38>Nov 18 10:15:02 OpenWrt dropbear[1235]: Password auth succeeded for 'root' from 192.168.1.66:51517",
        b"<30>Nov 18 10:15:03 OpenWrt dnsmasq-dhcp[901]: DHCPACK(br-lan) 192.168.1.40",
        b"<38>1 2026-11-18T10:15:04Z pfsense sshd 77 - - Invalid user admin from 192.168.1.66 port 4000",
    ]
    fed = [writer.write(p(raw), "192.168.1.1", received) for raw in lines]
    assert fed == [True, True, False, True]

    router_log = writer.router_log.read_text(encoding="utf-8").splitlines()
    assert len(router_log) == 4
    assert (
        router_log[2]
        == "2026-11-18T10:20:00+00:00 OpenWrt dnsmasq-dhcp[901]: DHCPACK(br-lan) 192.168.1.40"
    )

    feed = writer.siem_feed.read_text(encoding="utf-8").splitlines()
    assert (
        feed[0]
        == "2026-11-18T10:20:00+00:00 router sshd[1234]: Failed password for root from 192.168.1.66 port 51515 ssh2"
    )

    parser = AuthLogParser(tz=UTC)
    events = [parser.parse(line) for line in feed]
    assert [e.type for e in events] == [
        EventType.SSH_FAILED,
        EventType.SSH_ACCEPTED,
        EventType.SSH_INVALID_USER,
    ]
    assert {e.host for e in events} == {"router"}
    assert events[0].src_ip == "192.168.1.66"
    assert events[0].user == "root"


def test_message_timestamps_option(tmp_path):
    writer = RouterLogWriter(tmp_path, use_message_time=True)
    writer.write(
        p(b"<38>Nov 18 10:15:01 gw sshd[1]: hello"), "192.168.1.1", NOW + timedelta(hours=1)
    )
    assert writer.router_log.read_text().startswith("2026-11-18T10:15:01+00:00 gw sshd[1]: hello")


def test_rotation_keeps_one_backup(tmp_path):
    writer = RouterLogWriter(tmp_path, max_bytes=4096)
    for i in range(100):
        writer.write(
            p(f"<13>Nov 18 10:15:01 gw app: message {i:03d} ".encode() + b"x" * 50), "10.0.0.1"
        )
    assert writer.router_log.stat().st_size <= 4096
    backup = tmp_path / "router.log.1"
    assert backup.exists()
    assert "message 099" in writer.router_log.read_text()


def test_unsafe_hostnames_fall_back_to_sender(tmp_path):
    writer = RouterLogWriter(tmp_path)
    msg = p(b"<13>1 2026-11-18T10:15:01Z bad/host app - - - x")
    writer.write(msg, "192.168.1.1", NOW)
    assert writer.router_log.read_text().split()[1] == "192.168.1.1"


def send_udp(port: int, payloads: list[bytes]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for payload in payloads:
            s.sendto(payload, ("127.0.0.1", port))


async def wait_for(predicate, timeout=3.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not predicate():
        if loop.time() > end:
            raise AssertionError("timed out waiting for datagrams")
        await asyncio.sleep(0.02)


def test_udp_receiver_end_to_end(tmp_path):
    cfg = SyslogConfig(host="127.0.0.1", port=0, output_dir=str(tmp_path / "router-logs"))
    receiver = build_receiver(cfg)

    async def go():
        port = await receiver.start(cfg.host, cfg.port)
        assert port != 0
        try:
            await asyncio.to_thread(
                send_udp,
                port,
                [
                    b"<38>Nov 18 10:15:01 OpenWrt dropbear[1]: Bad password attempt for 'root' from 192.168.1.66:5000",
                    b"<38>1 2026-11-18T10:15:04Z OpenWrt sshd 2 - - Invalid user admin from 192.168.1.66 port 4000",
                    b"<30>Nov 18 10:15:05 OpenWrt kernel: br-lan: port 2(lan2) entered forwarding state",
                ],
            )
            await wait_for(lambda: receiver.stats.written == 3)
        finally:
            receiver.stop()

    asyncio.run(go())
    assert receiver.stats.to_siem == 2
    feed = receiver.writer.siem_feed.read_text().splitlines()
    assert "router sshd[1]: Failed password for root from 192.168.1.66 port 5000 ssh2" in feed[0]
    assert "kernel: br-lan" in receiver.writer.router_log.read_text()


def test_udp_receiver_drops_disallowed_senders(tmp_path):
    cfg = SyslogConfig(
        host="127.0.0.1", port=0, output_dir=str(tmp_path), allowed_senders=["192.168.1.1/32"]
    )
    receiver = build_receiver(cfg)

    async def go():
        port = await receiver.start(cfg.host, cfg.port)
        try:
            await asyncio.to_thread(send_udp, port, [b"<13>Nov 18 10:15:01 gw app: spoofed"])
            await wait_for(lambda: receiver.stats.received == 1)
        finally:
            receiver.stop()

    asyncio.run(go())
    assert receiver.stats.dropped_sender == 1
    assert receiver.stats.written == 0
    assert not receiver.writer.router_log.exists()


def test_sender_allowlist_handles_ipv4_mapped_addresses(tmp_path):
    receiver = SyslogReceiver(RouterLogWriter(tmp_path), ["192.168.1.0/24"])
    assert receiver.sender_allowed("::ffff:192.168.1.1")
    assert not receiver.sender_allowed("::ffff:10.0.0.1")
    assert not receiver.sender_allowed("garbage")
