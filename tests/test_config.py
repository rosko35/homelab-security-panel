from pathlib import Path

import pytest

from homesec.config import load_config, parse_duration

from conftest import ROOT


@pytest.mark.parametrize(
    ("value", "seconds"),
    [(90, 90), ("90", 90), ("90s", 90), ("5m", 300), ("6h", 21600), ("7d", 604800), ("1w", 604800)],
)
def test_parse_duration(value, seconds):
    assert parse_duration(value) == seconds


@pytest.mark.parametrize("value", ["", "soon", "-5m", "0", True])
def test_parse_duration_rejects(value):
    with pytest.raises(ValueError):
        parse_duration(value)


def test_shipped_config_loads_and_resolves_paths():
    cfg = load_config(ROOT / "config" / "homesec.yml", env={})
    assert cfg.scan.interval == 7 * 86400
    assert cfg.discovery.interval == 300
    assert Path(cfg.database) == (ROOT / "data" / "homesec.db").resolve()
    assert cfg.influx.url is None
    assert cfg.influx.token is None
    assert cfg.syslog.host == "127.0.0.1"


def test_env_overrides(tmp_path):
    env = {
        "HOMESEC_DB": "/data/homesec.db",
        "HOMESEC_NETWORKS": "192.168.178.0/24, 10.0.0.0/24",
        "INFLUX_URL": "http://influxdb:8086",
        "INFLUX_TOKEN": "secret",
        "SYSLOG_HOST": "0.0.0.0",
        "SYSLOG_PORT": "1514",
        "HOMESEC_SIEM_DB": "/siem-data/siem.db",
    }
    cfg = load_config(ROOT / "config" / "homesec.yml", env=env)
    assert cfg.database == "/data/homesec.db"
    assert cfg.discovery.networks == ["192.168.178.0/24", "10.0.0.0/24"]
    assert cfg.influx.url == "http://influxdb:8086"
    assert cfg.influx.token == "secret"
    assert "secret" not in str(cfg.model_dump())
    assert (cfg.syslog.host, cfg.syslog.port) == ("0.0.0.0", 1514)
    assert cfg.siem_export.database == "/siem-data/siem.db"


def test_secrets_in_yaml_are_refused(tmp_path):
    f = tmp_path / "c.yml"
    f.write_text("influx:\n  token: abc\n", encoding="utf-8")
    with pytest.raises(ValueError, match="INFLUX_TOKEN"):
        load_config(f, env={})


def test_unknown_keys_and_bad_networks_fail(tmp_path):
    f = tmp_path / "c.yml"
    f.write_text("scan:\n  intervall: 7d\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(f, env={})
    f.write_text("discovery:\n  networks: [fe80::/64]\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(f, env={})


def test_missing_explicit_config_fails(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.yml", env={})
