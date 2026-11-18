"""A small syslog (UDP) receiver for router logs.

Most home routers (OpenWrt, pfSense/OPNsense, FRITZ!Box with Freetz, many
ISP boxes) can send their log to a "remote syslog server". This receiver
accepts RFC 3164 (BSD) and RFC 5424 messages and writes two files:

``router.log``
    every message, one line each, ``<RFC 3339 time> <host> <app>[pid]: <msg>``
``router-siem.log``
    only SSH-related lines, in the format mini-siem's ``auth`` parser reads,
    with the hostname normalised to ``syslog.feed_hostname`` (default
    ``router``) so mini-siem rules can match ``host: router``. Dropbear (the
    SSH server on OpenWrt and many embedded routers) is translated into the
    equivalent OpenSSH wording, because mini-siem only understands sshd.

One datagram is one line: CR/LF and other control characters are replaced,
so a crafted message cannot inject fake log lines into the files mini-siem
trusts. Rotation is "create" style (``router.log`` -> ``router.log.1``),
which mini-siem's tailer follows by inode.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

log = logging.getLogger(__name__)

MAX_DATAGRAM = 8192
MAX_MESSAGE = 2000

ROUTER_LOG = "router.log"
SIEM_FEED = "router-siem.log"

_PRI = re.compile(rb"^<(\d{1,3})>")
_5424 = re.compile(
    r"^(?P<ver>[1-9]\d?) (?P<ts>-|\d{4}-\d{2}-\d{2}T\S+) (?P<host>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) ?(?P<rest>.*)$",
    re.DOTALL,
)
_3164_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) ?"
)
_ISO_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})) "
)
_TAG = re.compile(r"^(?P<app>[^\s\[\]:]{1,48})(?:\[(?P<pid>[^\]\s]{0,16})\])?:(?: |$)")
_SAFE_TOKEN = re.compile(r"^[\w.-]{1,64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
)}  # fmt: skip


@dataclass
class SyslogMessage:
    facility: int
    severity: int
    message: str
    timestamp: datetime | None = None
    hostname: str | None = None
    app: str | None = None
    procid: str | None = None
    msgid: str | None = None
    structured_data: str | None = None
    format: str = "rfc3164"


def sanitize(text: str, limit: int = MAX_MESSAGE) -> str:
    """Collapse control characters (CR/LF included) so one message = one line."""
    return _CONTROL.sub(" ", text).strip()[:limit]


def _nil(value: str) -> str | None:
    return None if value == "-" else value


def _parse_iso(value: str) -> datetime | None:
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def _split_structured_data(rest: str) -> tuple[str | None, str]:
    """RFC 5424 STRUCTURED-DATA is ``-`` or one or more ``[...]`` (``\\]`` escapes)."""
    if rest.startswith("-"):
        return None, rest[1:].lstrip(" ")
    if not rest.startswith("["):
        return None, rest
    i, depth, escaped = 0, 0, False
    while i < len(rest):
        ch = rest[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0 and (i + 1 == len(rest) or rest[i + 1] != "["):
                return rest[: i + 1], rest[i + 1 :].lstrip(" ")
        i += 1
    return rest, ""  # unterminated: treat it all as structured data


def _classic_ts(m: re.Match, tz: tzinfo, now: datetime) -> datetime | None:
    try:
        hh, mm, ss = (int(x) for x in m["time"].split(":"))
        ts = datetime(now.year, _MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, tzinfo=tz)
    except (KeyError, ValueError):
        return None
    if ts - now > timedelta(days=1):  # December log read in January
        ts = ts.replace(year=now.year - 1)
    return ts


def parse_syslog(
    data: bytes, *, tz: tzinfo | None = None, now: datetime | None = None
) -> SyslogMessage:
    """Parse one datagram. Never raises: unknown shapes become a plain message."""
    tz = tz or datetime.now().astimezone().tzinfo or UTC
    now = now or datetime.now(tz)
    facility, severity = 1, 5  # RFC 3164 4.3.3 default: user.notice
    m = _PRI.match(data)
    if m and int(m[1]) <= 191:
        pri = int(m[1])
        facility, severity = pri // 8, pri % 8
        data = data[m.end() :]
    text = data.decode("utf-8", errors="replace").lstrip("﻿")

    if m5 := _5424.match(text):
        sd, msg = _split_structured_data(m5["rest"])
        return SyslogMessage(
            facility=facility,
            severity=severity,
            message=sanitize(msg.lstrip("﻿")),
            timestamp=_parse_iso(m5["ts"]) if m5["ts"] != "-" else None,
            hostname=_nil(m5["host"]),
            app=_nil(m5["app"]),
            procid=_nil(m5["procid"]),
            msgid=_nil(m5["msgid"]),
            structured_data=sanitize(sd) if sd else None,
            format="rfc5424",
        )

    msg = SyslogMessage(facility, severity, "", format="rfc3164")
    if mt := _3164_TS.match(text):
        msg.timestamp = _classic_ts(mt, tz, now)
        text = text[mt.end() :]
    elif mi := _ISO_TS.match(text):
        msg.timestamp = _parse_iso(mi["ts"])
        text = text[mi.end() :]
    else:
        msg.format = "raw"

    # "<host> <tag>[pid]: msg" or, from many embedded devices, just "<tag>[pid]: msg".
    if msg.format != "raw" and not _TAG.match(text):
        host, _, remainder = text.partition(" ")
        if host and _SAFE_TOKEN.match(host):
            msg.hostname = host
            text = remainder
    if mtag := _TAG.match(text):
        msg.app, msg.procid = mtag["app"], mtag["pid"] or None
        text = text[mtag.end() :]
    msg.message = sanitize(text)
    return msg


# -- dropbear -> OpenSSH wording (mini-siem's auth parser only knows sshd) ------

_DB_BAD_PW = re.compile(r"^Bad password attempt for '(?P<user>.*)' from (?P<addr>\S+)$")
_DB_NO_USER = re.compile(
    r"^Login attempt for nonexistent user(?: '(?P<user>.*)')? from (?P<addr>\S+)$"
)
_DB_OK = re.compile(
    r"^(?P<method>Password|Pubkey) auth succeeded for '(?P<user>.*?)'(?: with .*?)? "
    r"from (?P<addr>\S+)$"
)


def _split_addr(addr: str) -> tuple[str, str] | None:
    """``1.2.3.4:5555`` / ``[2001:db8::1]:5555`` -> (ip, port)."""
    if addr.startswith("["):
        host, _, port = addr[1:].partition("]:")
    else:
        host, _, port = addr.rpartition(":")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return (host, port) if port.isdigit() else None


def translate_dropbear(message: str) -> str | None:
    if m := _DB_BAD_PW.match(message):
        if addr := _split_addr(m["addr"]):
            return f"Failed password for {m['user']} from {addr[0]} port {addr[1]} ssh2"
    elif m := _DB_NO_USER.match(message):
        if addr := _split_addr(m["addr"]):
            return f"Invalid user {m['user'] or 'unknown'} from {addr[0]} port {addr[1]}"
    elif (m := _DB_OK.match(message)) and (addr := _split_addr(m["addr"])):
        method = "password" if m["method"] == "Password" else "publickey"
        return f"Accepted {method} for {m['user']} from {addr[0]} port {addr[1]} ssh2"
    return None


# -- writer ---------------------------------------------------------------------


def _token(value: str | None, fallback: str) -> str:
    return value if value and _SAFE_TOKEN.match(value) else fallback


class RouterLogWriter:
    def __init__(
        self,
        output_dir: str | Path,
        *,
        feed_hostname: str = "router",
        translate: bool = True,
        use_message_time: bool = False,
        max_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self.dir = Path(output_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.feed_hostname = feed_hostname
        self.translate = translate
        self.use_message_time = use_message_time
        self.max_bytes = max_bytes

    @property
    def router_log(self) -> Path:
        return self.dir / ROUTER_LOG

    @property
    def siem_feed(self) -> Path:
        return self.dir / SIEM_FEED

    def _append(self, path: Path, line: str) -> None:
        data = (line + "\n").encode("utf-8")
        try:
            if path.stat().st_size + len(data) > self.max_bytes:
                os.replace(path, path.with_name(path.name + ".1"))
        except FileNotFoundError:
            pass
        with open(path, "ab") as fh:
            fh.write(data)

    def write(self, msg: SyslogMessage, sender: str, received: datetime | None = None) -> bool:
        """Write ``msg``; return True if it also went to the mini-siem feed."""
        received = received or datetime.now(UTC)
        ts = msg.timestamp if (self.use_message_time and msg.timestamp) else received
        stamp = ts.astimezone(UTC).isoformat(timespec="seconds")
        app = _token(msg.app, "-")
        pid = f"[{msg.procid}]" if msg.procid and _SAFE_TOKEN.match(msg.procid) else ""
        host = _token(msg.hostname, sender)
        self._append(self.router_log, f"{stamp} {host} {app}{pid}: {msg.message}")

        feed_msg = None
        if app in ("sshd", "sshd-session"):
            feed_msg, feed_app = msg.message, app
        elif app == "dropbear" and self.translate:
            feed_msg, feed_app = translate_dropbear(msg.message), "sshd"
        if feed_msg is None:
            return False
        self._append(self.siem_feed, f"{stamp} {self.feed_hostname} {feed_app}{pid}: {feed_msg}")
        return True


# -- UDP server -----------------------------------------------------------------


@dataclass
class ReceiverStats:
    received: int = 0
    written: int = 0
    to_siem: int = 0
    dropped_sender: int = 0
    errors: int = 0


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: SyslogReceiver) -> None:
        self.receiver = receiver

    def datagram_received(self, data: bytes, addr) -> None:
        self.receiver.handle(data[:MAX_DATAGRAM], addr[0])

    def error_received(self, exc: Exception) -> None:
        log.debug("syslog socket error: %s", exc)


class SyslogReceiver:
    def __init__(
        self,
        writer: RouterLogWriter,
        allowed_senders: list[str] | None = None,
    ) -> None:
        self.writer = writer
        self.allowed = [ipaddress.ip_network(n, strict=False) for n in (allowed_senders or [])]
        self.stats = ReceiverStats()
        self._transport: asyncio.DatagramTransport | None = None
        self._warned: set[str] = set()

    def sender_allowed(self, ip: str) -> bool:
        if not self.allowed:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.version == 6 and addr.ipv4_mapped:  # dual-stack sockets
            addr = addr.ipv4_mapped
        return any(addr in net for net in self.allowed)

    def handle(self, data: bytes, sender: str) -> None:
        self.stats.received += 1
        if not self.sender_allowed(sender):
            self.stats.dropped_sender += 1
            if sender not in self._warned:
                self._warned.add(sender)
                log.warning("syslog: dropping messages from %s (not in allowed_senders)", sender)
            return
        try:
            if self.writer.write(parse_syslog(data), sender):
                self.stats.to_siem += 1
            self.stats.written += 1
        except Exception:
            self.stats.errors += 1
            log.exception("syslog: cannot write message from %s", sender)

    async def start(self, host: str, port: int) -> int:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(self), local_addr=(host, port)
        )
        self._transport = transport
        bound = transport.get_extra_info("sockname")[1]
        log.info("syslog receiver listening on udp://%s:%d -> %s", host, bound, self.writer.dir)
        return bound

    def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    async def serve(self, host: str, port: int, stop: asyncio.Event) -> None:
        await self.start(host, port)
        try:
            await stop.wait()
        finally:
            self.stop()
            log.info("syslog receiver stopped (%s)", self.stats)


def build_receiver(cfg) -> SyslogReceiver:
    """``cfg`` is a :class:`homesec.config.SyslogConfig`."""
    writer = RouterLogWriter(
        cfg.output_dir,
        feed_hostname=cfg.feed_hostname,
        translate=cfg.translate_dropbear,
        use_message_time=cfg.timestamps == "message",
        max_bytes=cfg.max_bytes,
    )
    return SyslogReceiver(writer, cfg.allowed_senders)
