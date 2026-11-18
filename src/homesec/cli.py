"""Command line interface: ``homesec <command>``.

homesec run [--only discovery,scan,siem_export,syslog]   everything, scheduled
homesec discover [--once]                                device discovery
homesec scan [--once]                                    port scan of the inventory
homesec export-siem [--once]                             mini-siem -> InfluxDB
homesec syslog                                           router syslog receiver only
homesec devices list|known|unknown|label|forget          manage the inventory
homesec status                                           last job runs and scans
homesec check-config                                     validate the config file
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from homesec import __version__
from homesec.config import Config, load_config
from homesec.influx import build_writer
from homesec.inventory import DeviceNotFound, Inventory
from homesec.notify import build_notifier
from homesec.scheduler import Scheduler, install_stop_handlers

log = logging.getLogger("homesec")

JOB_NAMES = ("discovery", "scan", "siem_export", "syslog")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # httpx logs request URLs at INFO, and the Telegram URL contains the bot token.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def load_dotenv(path: str | Path = ".env") -> None:
    """Tiny .env reader for running outside Docker. Existing variables win."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().removeprefix("export ").strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _fmt_time(epoch: float | None) -> str:
    if not epoch:
        return "-"
    return datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M")


# -- job wiring ------------------------------------------------------------------


def _build_jobs(cfg: Config, inventory: Inventory, names: set[str], notifier, metrics) -> list:
    jobs: list = []
    if "discovery" in names:
        from homesec.jobs.discovery import DiscoveryJob

        jobs.append(DiscoveryJob(cfg.discovery, inventory, notifier, metrics))
    if "scan" in names:
        from homesec.jobs.scan import ScanJob

        jobs.append(ScanJob(cfg.scan, cfg.reports_dir, inventory, notifier, metrics))
    if "siem_export" in names:
        from homesec.jobs.siem_export import SiemExportJob

        jobs.append(SiemExportJob(cfg.siem_export, metrics))
    return jobs


def _enabled(cfg: Config) -> set[str]:
    return {
        name
        for name, on in (
            ("discovery", cfg.discovery.enabled),
            ("scan", cfg.scan.enabled),
            ("siem_export", cfg.siem_export.enabled),
            ("syslog", cfg.syslog.enabled),
        )
        if on
    }


async def _serve(cfg: Config, names: set[str], once: bool) -> int:
    inventory = Inventory(cfg.database)
    notifier = build_notifier()
    metrics = build_writer(cfg.influx)
    log.info("notifications: %s", notifier.name)
    try:
        jobs = _build_jobs(cfg, inventory, names, notifier, metrics)
        scheduler = Scheduler(jobs, inventory)
        if once:
            failed = False
            for job in jobs:
                summary = await scheduler.run_job(job)
                failed |= summary is None
                if summary is not None:
                    print(json.dumps({job.name: summary}, indent=2, default=str))
            return 1 if failed else 0

        stop = asyncio.Event()
        install_stop_handlers(stop)
        tasks = [asyncio.create_task(scheduler.run_forever(stop), name="scheduler")]
        if "syslog" in names:
            from homesec.syslog import build_receiver

            receiver = build_receiver(cfg.syslog)
            tasks.append(
                asyncio.create_task(
                    receiver.serve(cfg.syslog.host, cfg.syslog.port, stop), name="syslog"
                )
            )
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
            for task in done:
                if task.exception():
                    raise task.exception()  # type: ignore[misc]
        finally:
            stop.set()
            for task in tasks:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(task, timeout=scheduler.grace + 2)
        return 0
    finally:
        await notifier.aclose()
        await metrics.aclose()
        inventory.close()


def _run(cfg: Config, names: set[str], once: bool) -> int:
    try:
        return asyncio.run(_serve(cfg, names, once))
    except KeyboardInterrupt:  # Windows has no SIGTERM handler; Ctrl+C lands here
        return 0


# -- commands --------------------------------------------------------------------


def cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    names = _enabled(cfg)
    if args.only:
        wanted = {n.strip() for n in args.only.split(",") if n.strip()}
        unknown = wanted - set(JOB_NAMES)
        if unknown:
            print(f"unknown job(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        names = wanted
    if not names:
        print("nothing to run: every job is disabled", file=sys.stderr)
        return 2
    log.info("homesec %s starting: %s", __version__, ", ".join(sorted(names)))
    return _run(cfg, names, once=False)


def _single(name: str):
    def command(cfg: Config, args: argparse.Namespace) -> int:
        return _run(cfg, {name}, once=args.once)

    return command


def cmd_syslog(cfg: Config, args: argparse.Namespace) -> int:
    return _run(cfg, {"syslog"}, once=False)


def cmd_devices(cfg: Config, args: argparse.Namespace) -> int:
    with Inventory(cfg.database) as inv:
        try:
            if args.action == "list":
                devices = inv.devices(unknown_only=args.unknown)
                if args.json:
                    print(json.dumps([d.__dict__ for d in devices], indent=2))
                    return 0
                if not devices:
                    print("No devices yet. Run: homesec discover --once")
                    return 0
                print(f"{'MAC':<18} {'IP':<16} {'KNOWN':<6} {'LABEL':<20} {'VENDOR':<28} LAST SEEN")
                for d in devices:
                    print(
                        f"{d.mac:<18} {d.ip:<16} {'yes' if d.known else 'NO':<6} "
                        f"{(d.label or '-')[:20]:<20} {d.vendor[:28]:<28} {_fmt_time(d.last_seen)}"
                    )
                return 0
            if args.action == "known":
                d = inv.set_known(args.device, True, label=args.label)
                suffix = f", label '{d.label}'" if d.label else ""
                print(f"{d.mac} ({d.ip}) marked as known{suffix}")
            elif args.action == "unknown":
                d = inv.set_known(args.device, False)
                print(f"{d.mac} ({d.ip}) marked as unknown")
            elif args.action == "label":
                d = inv.set_label(args.device, args.label)
                print(f"{d.mac} ({d.ip}) labelled '{d.label}'")
            elif args.action == "forget":
                inv.forget(args.device)
                print(f"{args.device} removed from the inventory")
        except DeviceNotFound as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return 0


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    with Inventory(cfg.database) as inv:
        counts = inv.counts(online_since=time.time() - cfg.discovery.interval * 1.5)
        print(
            f"Devices: {counts['total']} ({counts['known']} known, {counts['unknown']} unknown, "
            f"{counts['online']} online)"
        )
        print("\nJobs:")
        for run in inv.job_runs():
            err = f"  {run['error']}" if run["error"] else ""
            print(f"  {run['name']:<12} {_fmt_time(run['last_run'])}  {run['status']}{err}")
        print("\nRecent scans:")
        for s in inv.scans(limit=5):
            print(
                f"  {_fmt_time(s.started)}  {s.hosts} host(s), {s.open_ports} open port(s), "
                f"{s.changes} change(s)  {s.report_path}"
            )
    return 0


def cmd_check_config(cfg: Config, args: argparse.Namespace) -> int:
    print(json.dumps(cfg.model_dump(), indent=2, default=str))
    print("config OK", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="homesec",
        description="Home network security panel. Only monitor networks you own.",
    )
    p.add_argument(
        "-c", "--config", help="YAML config (default: $HOMESEC_CONFIG or config/homesec.yml)"
    )
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run every enabled job on its schedule + the syslog receiver")
    r.add_argument("--only", help="comma separated subset: " + ",".join(JOB_NAMES))
    r.set_defaults(func=cmd_run)

    for name, job, text in (
        ("discover", "discovery", "discover devices and alert on unknown MACs"),
        ("scan", "scan", "port scan the inventory and alert on changes"),
        ("export-siem", "siem_export", "export mini-siem aggregates to InfluxDB"),
    ):
        sp = sub.add_parser(name, help=text)
        sp.add_argument("--once", action="store_true", help="run once and exit")
        sp.set_defaults(func=_single(job))

    sub.add_parser("syslog", help="run only the router syslog receiver").set_defaults(
        func=cmd_syslog
    )

    d = sub.add_parser("devices", help="list and manage the device inventory")
    dsub = d.add_subparsers(dest="action", required=True)
    dl = dsub.add_parser("list", help="list devices")
    dl.add_argument("--unknown", action="store_true", help="only devices not marked as known")
    dl.add_argument("--json", action="store_true")
    dk = dsub.add_parser("known", help="mark a device (MAC or current IP) as known")
    dk.add_argument("device")
    dk.add_argument("--label")
    du = dsub.add_parser("unknown", help="mark a device as unknown again")
    du.add_argument("device")
    dlab = dsub.add_parser("label", help="set a device's label")
    dlab.add_argument("device")
    dlab.add_argument("label")
    df = dsub.add_parser("forget", help="remove a device from the inventory")
    df.add_argument("device")
    d.set_defaults(func=cmd_devices)

    sub.add_parser("status", help="last job runs and scans").set_defaults(func=cmd_status)
    sub.add_parser("check-config", help="validate and print the configuration").set_defaults(
        func=cmd_check_config
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    load_dotenv()
    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    return args.func(cfg, args)
