"""Static checks for docker-compose.yml, Grafana provisioning and dashboards.

Docker itself is not needed: the compose file is parsed as YAML and the
``${VAR:-default}`` interpolation is evaluated with the values from
.env.example, which is what a fresh install gets.
"""

import json
import re
from pathlib import Path

import pytest
import yaml

from conftest import ROOT, SIBLINGS

COMPOSE = ROOT / "docker-compose.yml"
DASHBOARDS = ROOT / "grafana" / "dashboards"
OVERVIEW = DASHBOARDS / "Home security" / "home-security-overview.json"
IOT = DASHBOARDS / "IoT" / "iot-overview.json"

_VAR = re.compile(r"\$\{(?P<name>\w+)(?:(?P<op>:?[-?])(?P<arg>[^}]*))?\}")


def env_example() -> dict[str, str]:
    out = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            out[key] = value
    return out


def interpolate(value, env):
    if isinstance(value, dict):
        return {k: interpolate(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [interpolate(v, env) for v in value]
    if not isinstance(value, str):
        return value

    def repl(m):
        name, op, arg = m["name"], m["op"], m["arg"]
        current = env.get(name)
        if op in (":-", "-"):
            return current if current else arg
        if op in (":?", "?"):
            if not current:
                raise KeyError(f"{name} required: {arg}")
            return current
        return current or ""

    return _VAR.sub(repl, value)


@pytest.fixture(scope="module")
def raw_compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def compose(raw_compose):
    env = env_example()
    env.update(
        INFLUX_ADMIN_PASSWORD="test-password", INFLUX_TOKEN="test-token",
        GRAFANA_ADMIN_PASSWORD="test-password",
    )  # fmt: skip
    return interpolate(raw_compose, env)


def test_required_secrets_have_no_defaults(raw_compose):
    with pytest.raises(KeyError, match="INFLUX"):
        interpolate(raw_compose, env_example())  # .env.example ships them empty
    text = COMPOSE.read_text(encoding="utf-8")
    for secret in ("INFLUX_TOKEN", "INFLUX_ADMIN_PASSWORD", "GRAFANA_ADMIN_PASSWORD"):
        assert re.search(r"\$\{" + secret + r":\?", text), secret
        assert not re.search(r"\$\{" + secret + r":-", text), secret


def test_expected_services(compose):
    assert set(compose["services"]) == {
        "mosquitto", "influxdb", "grafana", "iot-ingest", "iot-simulator",
        "mini-siem", "homesec", "homesec-discovery",
    }  # fmt: skip
    assert compose["services"]["iot-simulator"]["profiles"] == ["simulator"]


def published(service) -> list[str]:
    return [p if isinstance(p, str) else p["published"] for p in service.get("ports", [])]


def test_every_published_port_is_loopback_by_default(compose):
    seen = 0
    for name, svc in compose["services"].items():
        for port in published(svc):
            seen += 1
            assert port.startswith("127.0.0.1:"), f"{name} publishes {port} beyond loopback"
    assert seen == 5  # mosquitto, influxdb, grafana, mini-siem, syslog


def test_bind_variables_allow_deliberate_exposure(raw_compose):
    text = json.dumps(raw_compose)
    for var in ("GRAFANA_BIND", "SYSLOG_BIND", "MQTT_BIND"):
        assert "${" + var + ":-127.0.0.1}" in text


def test_privileges_are_isolated_to_discovery(compose):
    for name, svc in compose["services"].items():
        if name == "homesec-discovery":
            assert svc["network_mode"] == "host"
            assert svc["cap_drop"] == ["ALL"]
            assert svc["cap_add"] == ["NET_RAW"]
            assert svc["user"] == "10001"
            assert svc["read_only"] is True
            assert "ports" not in svc
            assert "privileged" not in svc
        else:
            assert svc.get("network_mode") is None, name
            assert not svc.get("cap_add"), name
            assert not svc.get("privileged"), name


def test_own_and_sibling_services_are_hardened(compose):
    for name in ("homesec", "mini-siem", "iot-ingest", "iot-simulator"):
        svc = compose["services"][name]
        assert svc["read_only"] is True, name
        assert svc["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in svc["security_opt"], name


def test_resource_limits_and_pinned_images(compose):
    for name, svc in compose["services"].items():
        assert "mem_limit" in svc, name
        assert "cpus" in svc, name
        image = svc.get("image", "")
        assert not image.endswith(":latest"), name
        if "build" not in svc and svc.get("pull_policy") != "never":
            assert re.search(r":\d+\.\d+", image), f"{name}: pin an image version"


def test_sibling_builds_default_to_github_and_are_overridable(raw_compose):
    services = raw_compose["services"]
    contexts = {
        "iot-ingest": services["iot-ingest"]["build"]["context"],
        "mini-siem": services["mini-siem"]["build"]["context"],
        "homesec": services["homesec"]["build"]["additional_contexts"]["scanner"],
        "homesec-discovery": services["homesec-discovery"]["build"]["additional_contexts"][
            "scanner"
        ],
    }
    assert contexts == {
        "iot-ingest": "${IOT_SRC:-https://github.com/rosko35/iot-sensor-panel.git#main}",
        "mini-siem": "${SIEM_SRC:-https://github.com/rosko35/mini-siem.git#main}",
        "homesec": "${SCANNER_SRC:-https://github.com/rosko35/async-vuln-scanner.git#main}",
        "homesec-discovery": "${SCANNER_SRC:-https://github.com/rosko35/async-vuln-scanner.git#main}",
    }


def test_bind_mount_sources_exist(compose):
    for name, svc in compose["services"].items():
        for volume in svc.get("volumes", []):
            source = volume.split(":", 1)[0]
            if source.startswith("./"):
                assert (ROOT / source).exists(), f"{name}: {source} missing"


def test_shared_volumes_wire_the_services_together(compose):
    def mounts(name):
        return {v.split(":")[0]: v for v in compose["services"][name]["volumes"]}

    assert mounts("mini-siem")["router-logs"].endswith(":ro")
    assert "router-logs" in mounts("homesec")
    assert mounts("homesec")["siem-data"].startswith("siem-data:/siem-data")
    assert mounts("mini-siem")["siem-data"] == "siem-data:/data"
    assert "homesec-data" in mounts("homesec-discovery")
    env = compose["services"]["homesec"]["environment"]
    assert env["HOMESEC_SIEM_DB"] == "/siem-data/siem.db"
    assert env["HOMESEC_SYSLOG_DIR"] == "/router-logs"
    assert compose["services"]["homesec-discovery"]["environment"]["INFLUX_URL"].startswith(
        "http://127.0.0.1:"
    )


def test_no_secrets_committed():
    env = env_example()
    for key, value in env.items():
        if any(w in key for w in ("TOKEN", "PASSWORD", "API_KEY", "CHAT_ID")):
            assert value == "", f".env.example must not ship a value for {key}"
    for path in ROOT.rglob("*"):
        if ".venv" in path.parts or ".git" in path.parts or not path.is_file():
            continue
        if path.suffix not in {
            ".yml",
            ".yaml",
            ".json",
            ".py",
            ".md",
            ".toml",
            ".conf",
            ".example",
        }:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not re.search(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", text), f"Telegram token in {path}"


def test_init_env_generates_secrets(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("init_env", ROOT / "scripts" / "init_env.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path / ".env"
    assert module.main(["--output", str(out)]) == 0
    values = dict(
        line.split("=", 1) for line in out.read_text().splitlines() if line and line[0] != "#"
    )
    assert len(values["INFLUX_TOKEN"]) >= 48
    assert len(values["GRAFANA_ADMIN_PASSWORD"]) >= 18
    assert values["TELEGRAM_BOT_TOKEN"] == ""
    assert module.main(["--output", str(out)]) == 1  # no silent overwrite


# ---------------------------------------------------------------- Grafana


def test_datasource_provisioning():
    data = yaml.safe_load((ROOT / "grafana/provisioning/datasources/influxdb.yml").read_text())
    (ds,) = data["datasources"]
    assert ds["uid"] == "influxdb"
    assert ds["url"] == "http://influxdb:8086"
    assert ds["jsonData"]["version"] == "Flux"
    assert ds["secureJsonData"]["token"] == "${INFLUX_TOKEN}"


def test_dashboard_provider_matches_compose_mounts(compose):
    data = yaml.safe_load((ROOT / "grafana/provisioning/dashboards/dashboards.yml").read_text())
    (provider,) = data["providers"]
    assert provider["options"]["foldersFromFilesStructure"] is True
    path = provider["options"]["path"]
    grafana = compose["services"]["grafana"]
    assert f"./grafana/dashboards:{path}:ro" in grafana["volumes"]
    home = grafana["environment"]["GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH"]
    assert (DASHBOARDS / Path(home).relative_to(path)).is_file()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def all_panels(dashboard):
    for p in dashboard["panels"]:
        yield p
        yield from p.get("panels", [])


def written_measurements() -> set[str]:
    names = set()
    for src in (ROOT / "src" / "homesec").rglob("*.py"):
        names |= set(re.findall(r'Point\(\s*"(\w+)"', src.read_text(encoding="utf-8")))
    return names


@pytest.mark.parametrize("path", [OVERVIEW, IOT], ids=["overview", "iot"])
def test_dashboards_are_valid(path):
    d = load(path)
    assert d["uid"] and d["title"]
    ids = [p["id"] for p in all_panels(d)]
    assert len(ids) == len(set(ids))
    for p in all_panels(d):
        for target in p.get("targets", []):
            assert target["datasource"]["uid"] == "influxdb"
            assert "from(bucket:" in target["query"]


def test_dashboard_uids_are_unique():
    uids = [load(p)["uid"] for p in DASHBOARDS.rglob("*.json")]
    assert len(uids) == len(set(uids)) == 2


def test_overview_has_the_promised_panels():
    d = load(OVERVIEW)
    titles = {p["title"] for p in all_panels(d)}
    for wanted in (
        "Devices",
        "New devices per day",
        "Open ports per device (latest scan)",
        "Scan changes",
        "CVEs by severity (latest scan)",
        "SIEM alerts per hour by rule",
        "Alerts by rule (selected range)",
        "IoT sensor dashboard",
    ):
        assert wanted in titles
    # link + text panel to the sensor dashboard, by its real uid
    assert any(link["url"] == "/d/" + load(IOT)["uid"] for link in d["links"])


def test_overview_queries_only_use_measurements_the_code_writes():
    used = set()
    for p in all_panels(load(OVERVIEW)):
        for t in p.get("targets", []):
            used |= set(re.findall(r'r\._measurement == "(\w+)"', t["query"]))
    ours = {m for m in used if m != "telemetry"}  # telemetry: iot-sensor-panel's ingest
    assert ours
    assert ours <= written_measurements(), ours - written_measurements()


def test_overview_buckets_are_template_constants():
    d = load(OVERVIEW)
    consts = {v["name"]: v["query"] for v in d["templating"]["list"] if v["type"] == "constant"}
    assert consts == {"hbucket": "homelab", "sbucket": "sensors"}
    for p in all_panels(d):
        for t in p.get("targets", []):
            assert re.findall(r"from\(bucket: ([^)]*)\)", t["query"])
            for bucket in re.findall(r"from\(bucket: ([^)]*)\)", t["query"]):
                assert bucket in ('"${hbucket}"', '"${sbucket}"')


def test_overview_layout_does_not_overlap():
    cells = set()
    for p in all_panels(load(OVERVIEW)):
        g = p["gridPos"]
        assert g["x"] >= 0 and g["x"] + g["w"] <= 24
        for x in range(g["x"], g["x"] + g["w"]):
            for y in range(g["y"], g["y"] + g["h"]):
                assert (x, y) not in cells, p["title"]
                cells.add((x, y))


def test_vendored_iot_dashboard_matches_sibling():
    upstream = SIBLINGS / "iot-sensor-panel" / "grafana" / "dashboards" / "iot-overview.json"
    if not upstream.is_file():
        pytest.skip("iot-sensor-panel checkout not next to this repository")
    assert load(IOT) == load(upstream), "run scripts/sync_iot_dashboard.py"


def test_dockerfile_targets():
    text = (ROOT / "docker" / "homesec.Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:3\.12-slim-bookworm AS homesec$", text, re.M)
    assert re.search(r"^FROM homesec AS discovery$", text, re.M)
    assert "setcap cap_net_raw+ep /usr/local/bin/python3-netraw" in text
    assert text.count("USER 10001") == 2
    assert "COPY --from=scanner" in text
