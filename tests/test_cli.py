import json

import pytest

from homesec.cli import load_dotenv, main
from homesec.inventory import Inventory, Sighting


@pytest.fixture
def config(tmp_path, monkeypatch):
    for var in ("HOMESEC_DB", "HOMESEC_CONFIG", "INFLUX_URL", "TELEGRAM_BOT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    cfg = tmp_path / "homesec.yml"
    cfg.write_text(
        "database: state/homesec.db\nsiem_export:\n  database: siem/siem.db\n",
        encoding="utf-8",
    )
    with Inventory(tmp_path / "state" / "homesec.db") as inv:
        inv.record(
            [
                Sighting("192.168.1.1", "3c:a6:2f:12:34:56", "AVM (FRITZ!Box)"),
                Sighting("192.168.1.40", "24:0a:c4:01:02:03", "Espressif"),
            ],
            now=1_700_000_000,
        )
    return cfg


def test_devices_list_known_label_forget(config, capsys):
    assert main(["-c", str(config), "devices", "list"]) == 0
    out = capsys.readouterr().out
    assert "3c:a6:2f:12:34:56" in out and "NO" in out

    assert main(["-c", str(config), "devices", "known", "192.168.1.1", "--label", "router"]) == 0
    assert "marked as known, label 'router'" in capsys.readouterr().out

    assert (
        main(["-c", str(config), "devices", "label", "24-0A-C4-01-02-03", "greenhouse sensor"]) == 0
    )
    capsys.readouterr()

    assert main(["-c", str(config), "devices", "list", "--unknown", "--json"]) == 0
    unknown = json.loads(capsys.readouterr().out)
    assert [(d["mac"], d["label"]) for d in unknown] == [("24:0a:c4:01:02:03", "greenhouse sensor")]

    assert main(["-c", str(config), "devices", "forget", "24:0a:c4:01:02:03"]) == 0
    assert main(["-c", str(config), "devices", "known", "24:0a:c4:01:02:03"]) == 1
    assert "no device with MAC" in capsys.readouterr().err


def test_export_siem_once_without_database_is_not_fatal(config, capsys):
    assert main(["-c", str(config), "export-siem", "--once"]) == 0
    assert '"skipped"' in capsys.readouterr().out


def test_status(config, capsys):
    assert main(["-c", str(config), "status"]) == 0
    assert "Devices: 2 (0 known, 2 unknown" in capsys.readouterr().out


def test_bad_config_and_unknown_job(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text("scan:\n  interval: often\n", encoding="utf-8")
    assert main(["-c", str(bad), "status"]) == 2
    assert "config error" in capsys.readouterr().err
    good = tmp_path / "good.yml"
    good.write_text("database: s.db\n", encoding="utf-8")
    assert main(["-c", str(good), "run", "--only", "coffee"]) == 2


def test_load_dotenv_does_not_override(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nHOMESEC_T1=from-file\nexport HOMESEC_T2='quoted'\nHOMESEC_T3=x\n")
    monkeypatch.setenv("HOMESEC_T3", "from-env")
    monkeypatch.delenv("HOMESEC_T1", raising=False)
    monkeypatch.delenv("HOMESEC_T2", raising=False)
    load_dotenv(env)
    import os

    assert os.environ["HOMESEC_T1"] == "from-file"
    assert os.environ["HOMESEC_T2"] == "quoted"
    assert os.environ["HOMESEC_T3"] == "from-env"
    monkeypatch.delenv("HOMESEC_T1")
    monkeypatch.delenv("HOMESEC_T2")
