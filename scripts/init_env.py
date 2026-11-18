"""Create .env from .env.example with strong random secrets.

    python scripts/init_env.py            # refuses to overwrite an existing .env
    python scripts/init_env.py --force

Only the required secrets are generated (InfluxDB admin password and token,
Grafana admin password); everything else is copied from .env.example.
"""

from __future__ import annotations

import argparse
import contextlib
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATED = {
    "INFLUX_ADMIN_PASSWORD": lambda: secrets.token_urlsafe(24),
    "INFLUX_TOKEN": lambda: secrets.token_urlsafe(48),
    "GRAFANA_ADMIN_PASSWORD": lambda: secrets.token_urlsafe(18),
}


def render(example: str) -> str:
    out = []
    for line in example.splitlines():
        key, sep, value = line.partition("=")
        if sep and not line.lstrip().startswith("#") and key in GENERATED and not value:
            line = f"{key}={GENERATED[key]()}"
        out.append(line)
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--example", type=Path, default=ROOT / ".env.example")
    parser.add_argument("--output", type=Path, default=ROOT / ".env")
    parser.add_argument("--force", action="store_true", help="overwrite an existing .env")
    args = parser.parse_args(argv)
    if args.output.exists() and not args.force:
        print(f"{args.output} exists; use --force to replace it", file=sys.stderr)
        return 1
    args.output.write_text(render(args.example.read_text(encoding="utf-8")), encoding="utf-8")
    with contextlib.suppress(OSError):
        args.output.chmod(0o600)
    print(f"wrote {args.output} (Grafana login: admin / see GRAFANA_ADMIN_PASSWORD)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
