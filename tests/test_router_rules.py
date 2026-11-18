"""siem/rules/router.yml, validated and executed by mini-siem's own code."""

from datetime import UTC, datetime

import pytest
import yaml
from minisiem.config import Config as SiemConfig
from minisiem.detection import load_rules
from minisiem.detection.engine import RuleEngine
from minisiem.parsers import AuthLogParser

from homesec.syslog import RouterLogWriter, parse_syslog

from conftest import ROOT, SIBLINGS

RULES = ROOT / "siem" / "rules" / "router.yml"


def test_router_rules_load_with_mini_siem_loader():
    rules = load_rules(RULES)
    assert {r.id for r in rules} == {
        "router-ssh-failures",
        "router-user-guessing",
        "router-shell-login",
        "router-login-after-failures",
    }
    for rule in rules:
        assert rule.id.startswith("router-")
        assert rule.match.get("host") == "router"  # never fires on the host's own sshd
        assert rule.mitre


def test_router_rules_coexist_with_mini_siem_default_rules(tmp_path):
    shipped = SIBLINGS / "mini-siem" / "rules"
    if not shipped.is_dir():
        pytest.skip("mini-siem checkout not next to this repository")
    for f in shipped.glob("*.yml"):
        (tmp_path / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "router.yml").write_text(RULES.read_text(encoding="utf-8"), encoding="utf-8")
    ids = [r.id for r in load_rules(tmp_path)]  # raises on duplicate ids
    assert len(ids) == len(set(ids))


def test_siem_config_is_valid_for_mini_siem():
    data = yaml.safe_load((ROOT / "siem" / "config.yml").read_text(encoding="utf-8"))
    cfg = SiemConfig.model_validate(data)
    paths = {s.path for s in cfg.sources}
    assert "/router-logs/router-siem.log" in paths
    assert all(s.parser == "auth" for s in cfg.sources)


def test_router_feed_triggers_router_rules(tmp_path):
    """syslog datagram -> homesec feed file -> mini-siem parser -> mini-siem rule engine."""
    writer = RouterLogWriter(tmp_path, feed_hostname="router")
    base = datetime(2026, 11, 18, 10, 0, tzinfo=UTC)
    raw = [
        b"<38>Nov 18 10:00:01 OpenWrt dropbear[11]: Bad password attempt for 'root' from 192.168.1.66:5001",
        b"<38>Nov 18 10:00:02 OpenWrt dropbear[12]: Login attempt for nonexistent user 'admin' from 192.168.1.66:5002",
        b"<38>Nov 18 10:00:03 OpenWrt dropbear[13]: Bad password attempt for 'root' from 192.168.1.66:5003",
        b"<38>Nov 18 10:00:04 OpenWrt dropbear[14]: Bad password attempt for 'ubnt' from 192.168.1.66:5004",
        b"<38>Nov 18 10:00:05 OpenWrt dropbear[15]: Password auth succeeded for 'root' from 192.168.1.66:5005",
    ]
    for i, datagram in enumerate(raw):
        received = base.replace(second=i + 1)
        writer.write(parse_syslog(datagram, tz=UTC, now=received), "192.168.1.1", received)

    parser = AuthLogParser(tz=UTC)
    engine = RuleEngine(load_rules(RULES))
    alerts = []
    for line in writer.siem_feed.read_text(encoding="utf-8").splitlines():
        event = parser.parse(line)
        assert event is not None, line
        alerts += engine.process(event)

    # Rules are evaluated in file order for every event.
    assert [a.rule_id for a in alerts] == [
        "router-ssh-failures",  # 3rd failed password (10:00:04)
        "router-user-guessing",  # 3rd distinct username: root, admin, ubnt (10:00:04)
        "router-shell-login",  # the login at 10:00:05 ...
        "router-login-after-failures",  # ... right after 3 failures
    ]
    by_id = {a.rule_id: a for a in alerts}
    assert by_id["router-ssh-failures"].src_ip == "192.168.1.66"
    assert "root" in by_id["router-shell-login"].message


def test_host_sshd_lines_do_not_trigger_router_rules():
    parser = AuthLogParser(tz=UTC)
    engine = RuleEngine(load_rules(RULES))
    alerts = []
    for sec in range(1, 6):
        line = f"2026-11-18T10:00:0{sec}+00:00 raspberrypi sshd[9]: Failed password for root from 203.0.113.9 port 4000{sec} ssh2"
        alerts += engine.process(parser.parse(line))
    assert alerts == []
