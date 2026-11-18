"""Configuration: a YAML file for behaviour, environment variables for secrets.

Relative paths in the YAML file are resolved against the file's directory.
Secrets are never read from the YAML file, only from the environment / ``.env``:

    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID     notifications (console when unset)
    INFLUX_TOKEN                             InfluxDB API token

Non-secret environment overrides (handy in Docker):

    HOMESEC_CONFIG          path of the YAML file (default: ./config/homesec.yml)
    HOMESEC_DB              state database path
    HOMESEC_REPORTS_DIR     where scan JSON reports are stored
    HOMESEC_NETWORKS        comma separated CIDRs for discovery
    HOMESEC_SIEM_DB         mini-siem database to export from
    HOMESEC_SYSLOG_DIR      where the syslog receiver writes router logs
    INFLUX_URL, INFLUX_ORG, HOMESEC_INFLUX_BUCKET
    SYSLOG_HOST, SYSLOG_PORT
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

DEFAULT_CONFIG = "config/homesec.yml"

_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$", re.IGNORECASE)
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}


def parse_duration(value: str | int | float) -> float:
    """``90`` / ``"90s"`` / ``"15m"`` / ``"6h"`` / ``"7d"`` / ``"1w"`` -> seconds."""
    if isinstance(value, bool):
        raise ValueError("duration must be a number or a string like '15m'")
    if isinstance(value, int | float):
        seconds = float(value)
    else:
        m = _DURATION.match(value)
        if not m:
            raise ValueError(f"invalid duration {value!r} (examples: 300, '5m', '6h', '7d')")
        seconds = float(m[1]) * _UNITS[m[2].lower()]
    if seconds <= 0:
        raise ValueError("duration must be positive")
    return seconds


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _duration_field(v):
    return parse_duration(v)


class DiscoveryConfig(_Strict):
    enabled: bool = True
    interval: float = 300.0
    # Networks to watch. ARP sweeps need them; neighbour-table results are filtered by them.
    networks: list[str] = Field(default_factory=lambda: ["192.168.1.0/24"])
    method: Literal["auto", "arp", "neighbours"] = "auto"
    arp_timeout: float = Field(default=2.0, gt=0)
    iface: str | None = None
    notify_unknown: bool = True
    # First run on an empty inventory: record everything, send one summary message
    # instead of one alert per device.
    baseline_first_run: bool = True
    # Optional full IEEE MA-L table (oui.csv from standards-oui.ieee.org).
    oui_file: str | None = None

    _interval = field_validator("interval", mode="before")(_duration_field)

    @field_validator("networks")
    @classmethod
    def _networks(cls, v: list[str]) -> list[str]:
        out = []
        for item in v:
            net = ipaddress.ip_network(item.strip(), strict=False)
            if net.version != 4:
                raise ValueError(f"{item}: only IPv4 networks are supported")
            out.append(str(net))
        return out


AlertKind = Literal[
    "new_host", "host_gone", "port_opened", "port_closed", "service_changed", "new_cve"
]


class ScanConfig(_Strict):
    enabled: bool = True
    interval: float = 7 * 86400.0
    ports: str = "top"
    cve: bool = True
    concurrency: int = Field(default=200, ge=1, le=5000)
    timeout: float = Field(default=1.0, gt=0)
    rate: float | None = Field(default=200.0, gt=0)
    # Only scan devices seen by discovery within this period.
    max_device_age: float = 7 * 86400.0
    exclude: list[str] = Field(default_factory=list)  # IPs or MACs never to scan
    alert_on: list[AlertKind] = Field(
        default_factory=lambda: ["new_host", "port_opened", "service_changed", "new_cve"]
    )
    keep_reports: int = Field(default=26, ge=2)
    nvd_cache_dir: str | None = None

    _interval = field_validator("interval", "max_device_age", mode="before")(_duration_field)


class SiemExportConfig(_Strict):
    enabled: bool = True
    interval: float = 60.0
    database: str = "data/siem/siem.db"
    lookback_hours: int = Field(default=48, ge=1, le=24 * 31)

    _interval = field_validator("interval", mode="before")(_duration_field)


class SyslogConfig(_Strict):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = Field(default=5514, ge=0, le=65535)
    output_dir: str = "data/router-logs"
    # Senders allowed to log (CIDRs). UDP is spoofable, so this is hygiene, not auth.
    allowed_senders: list[str] = Field(
        default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    )
    # Hostname written into the mini-siem feed, so rules can match `host: router`.
    feed_hostname: str = Field(default="router", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    translate_dropbear: bool = True
    timestamps: Literal["received", "message"] = "received"
    max_bytes: int = Field(default=10 * 1024 * 1024, ge=4096)


class InfluxConfig(_Strict):
    url: str | None = None  # unset = metrics are only logged at debug level
    org: str = "iot"
    bucket: str = "homelab"
    create_bucket: bool = True
    retention: float = 365 * 86400.0
    timeout: float = Field(default=10.0, gt=0)
    token: str | None = Field(default=None, exclude=True)  # from INFLUX_TOKEN only

    _retention = field_validator("retention", mode="before")(_duration_field)


class Config(_Strict):
    database: str = "data/homesec.db"
    reports_dir: str = "data/reports"
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    siem_export: SiemExportConfig = Field(default_factory=SiemExportConfig)
    syslog: SyslogConfig = Field(default_factory=SyslogConfig)
    influx: InfluxConfig = Field(default_factory=InfluxConfig)


def _resolve(base: Path, value: str | None) -> str | None:
    if not value:
        return value
    p = Path(value)
    return str(p if p.is_absolute() else (base / p).resolve())


def load_config(path: str | Path | None = None, env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    explicit = path is not None or "HOMESEC_CONFIG" in env
    path = Path(path or env.get("HOMESEC_CONFIG", DEFAULT_CONFIG))
    data: dict = {}
    if path.is_file():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected a mapping at the top level")
    elif explicit:
        raise FileNotFoundError(f"config file not found: {path}")
    if "token" in (data.get("influx") or {}):
        raise ValueError("influx.token must not be in the config file; set INFLUX_TOKEN instead")
    cfg = Config.model_validate(data)

    base = path.resolve().parent
    cfg.database = env.get("HOMESEC_DB") or _resolve(base, cfg.database) or cfg.database
    cfg.reports_dir = (
        env.get("HOMESEC_REPORTS_DIR") or _resolve(base, cfg.reports_dir) or cfg.reports_dir
    )
    cfg.siem_export.database = (
        env.get("HOMESEC_SIEM_DB")
        or _resolve(base, cfg.siem_export.database)
        or cfg.siem_export.database
    )
    cfg.syslog.output_dir = (
        env.get("HOMESEC_SYSLOG_DIR")
        or _resolve(base, cfg.syslog.output_dir)
        or cfg.syslog.output_dir
    )
    cfg.scan.nvd_cache_dir = _resolve(base, cfg.scan.nvd_cache_dir)
    cfg.discovery.oui_file = _resolve(base, cfg.discovery.oui_file)

    if nets := env.get("HOMESEC_NETWORKS", "").strip():
        cfg.discovery = DiscoveryConfig.model_validate(
            {**cfg.discovery.model_dump(), "networks": [n for n in nets.split(",") if n.strip()]}
        )
    if host := env.get("SYSLOG_HOST"):
        cfg.syslog.host = host
    if port := env.get("SYSLOG_PORT"):
        cfg.syslog.port = int(port)
    if url := env.get("INFLUX_URL"):
        cfg.influx.url = url
    if org := env.get("INFLUX_ORG"):
        cfg.influx.org = org
    if bucket := env.get("HOMESEC_INFLUX_BUCKET"):
        cfg.influx.bucket = bucket
    cfg.influx.token = env.get("INFLUX_TOKEN") or None
    return cfg
