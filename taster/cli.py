"""Shared entry for the slash command and `hermes taster`."""
from __future__ import annotations
import json
from pathlib import Path

from . import box, report


def taste_path(path: str, disclosure: str = "", as_json: bool = False) -> tuple[str, int]:
    d = Path(path).expanduser()
    if not (d / "__init__.py").exists():
        return f"Taster: no plugin found at {d} (need a folder with __init__.py).", 2
    try:
        result = box.taste(str(d))
    except ValueError as e:
        return f"Taster: cannot box this folder: {e}", 2
    fs = report.findings(result, report.load_manifest(str(d)), disclosure)
    if as_json:
        return json.dumps(report._clean_deep({"result": result, "findings": fs}), indent=2), int(any(f["level"] == "HIGH" for f in fs))
    name = report.load_manifest(str(d)).get("name", d.name)
    return report.render(name, result, fs), int(any(f["level"] == "HIGH" for f in fs))


def slash(raw_args: str) -> str:
    parts = (raw_args or "").split()
    if not parts:
        return "Usage: /taster <plugin-folder> [disclosure text]"
    return taste_path(parts[0], " ".join(parts[1:]))[0]


def setup(sub) -> None:
    sub.add_argument("path", help="plugin folder to run once in the box")
    sub.add_argument("--disclosure", default="", help="catalog Disclosure text to compare against")
    sub.add_argument("--json", action="store_true", help="machine-readable output")


def handler(args) -> int:
    text, code = taste_path(args.path, args.disclosure, args.json)
    print(text)
    return code
