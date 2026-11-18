"""Refresh grafana/dashboards/IoT/iot-overview.json from iot-sensor-panel.

The IoT dashboard is vendored (a compose bind mount cannot point into a git
build context). Run this after changing the dashboard in the sibling project:

    python scripts/sync_iot_dashboard.py                      # ../iot-sensor-panel
    python scripts/sync_iot_dashboard.py --source /path/to/iot-sensor-panel
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "grafana" / "dashboards" / "IoT" / "iot-overview.json"
RELATIVE = Path("grafana") / "dashboards" / "iot-overview.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, default=ROOT.parent / "iot-sensor-panel")
    args = parser.parse_args(argv)
    src = args.source / RELATIVE
    if not src.is_file():
        print(f"not found: {src}", file=sys.stderr)
        return 1
    text = src.read_text(encoding="utf-8")
    json.loads(text)  # refuse to copy something broken
    if TARGET.is_file() and TARGET.read_text(encoding="utf-8") == text:
        print("already up to date")
        return 0
    TARGET.write_text(text, encoding="utf-8")
    print(f"updated {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
