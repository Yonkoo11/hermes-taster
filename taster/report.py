"""Compare what a plugin did in the box with what it declared. Wording is always 'observed in this run'."""
from __future__ import annotations
import re
from pathlib import Path

COMMON_ENV = {"HOME", "PATH", "USER", "LANG", "TMPDIR", "TERM", "SHELL", "PWD", "HERMES_HOME", "TZ", "LOGNAME"}
NET_WORDS = re.compile(r"network|http|api|request|fetch|online|internet|url|rpc|webhook|download", re.I)
PROC_WORDS = re.compile(r"subprocess|shell|command|run|exec|spawn|cli|git|terminal", re.I)
FILE_WORDS = re.compile(r"file|read|write|disk|folder|director|config|log|cache|store|save", re.I)


def load_manifest(plugin_dir: str) -> dict:
    p = Path(plugin_dir) / "plugin.yaml"
    if not p.exists():
        return {}
    try:
        import yaml
        return yaml.safe_load(p.read_text()) or {}
    except Exception:
        return _mini_yaml(p.read_text())


def _mini_yaml(text: str) -> dict:
    """Fallback when PyYAML is missing: top-level scalars and simple '- item' lists."""
    out, key = {}, None
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            out[key] = m.group(2).strip().strip("\"'") if m.group(2).strip() else []
        elif key and re.match(r"^\s+-\s+", line) and isinstance(out.get(key), list):
            out[key].append(re.sub(r"^\s+-\s+", "", line).strip().strip("\"'"))
    return out


def _declared_env(m: dict) -> set:
    return {(e if isinstance(e, str) else e.get("name", "")) for e in m.get("requires_env", [])}


def _is_wallet(text: str, hints) -> bool:
    return any(h.lower() in text.lower() for h in hints)


def findings(result: dict, manifest: dict, disclosure: str = "", wallet_hints=("zaw", "zcash", "seed", "wallet", "zec", "shielded")) -> list[dict]:
    said = " ".join([str(manifest.get("description", "")), disclosure])
    out, seen = [], set()
    canary = set(result["canary_files"])
    for e in result["events"]:
        key = (e["kind"], e["target"])
        if key in seen:
            continue
        seen.add(key)
        f = _judge(e, canary, manifest, said, result, wallet_hints)
        if f:
            out.append({**f, "phase": e["phase"], "target": e["target"]})
    out += _registration_findings(result, manifest)
    if result["ended"] != "ok":
        out.append({"level": "HIGH", "what": "run did not finish cleanly: " + result["ended"] + " (events so far are partial)", "phase": "run", "target": ""})
    return sorted(out, key=lambda f: {"HIGH": 0, "MEDIUM": 1, "INFO": 2}[f["level"]])


def _judge(e, canary, manifest, said, result, hints):
    k, t = e["kind"], e["target"]
    if k in ("read", "write") and t in canary:
        wl = _is_wallet(t, hints)
        return {"level": "HIGH", "what": ("touched a canary wallet/secret file" if wl else "touched a canary secret file") + f" ({k})"}
    if k == "read" and t.startswith(result["home"]) and not t.endswith(".taster-out.json"):
        return {"level": "MEDIUM", "what": "read a file in the user's home" + ("" if FILE_WORDS.search(said) else " (files not mentioned in description)")}
    if k == "write":
        return {"level": "MEDIUM", "what": "wrote or deleted a file" + ("" if FILE_WORDS.search(said) else " (files not mentioned)")}
    if k == "env":
        return _judge_env(t, manifest, result)
    if k == "envall":
        return {"level": "MEDIUM", "what": "enumerated the whole environment (" + t + "), which includes any API keys the host has set"}
    if k == "proc" and any(c in t or c.replace(result["home"], "~") in t for c in canary):
        return {"level": "HIGH", "what": "started a subprocess whose command line names a canary file"}
    return _judge_action(k, t, said)


def _judge_env(name, manifest, result):
    if name in result["canary_env"] and name not in _declared_env(manifest):
        return {"level": "HIGH", "what": f"read canary env var {name} it does not declare in requires_env"}
    if name in COMMON_ENV or name in _declared_env(manifest) or name.startswith(("PYTHON", "LC_", "REDLINE")):
        return None
    return {"level": "INFO", "what": f"read env var {name} (not in requires_env)"}


def _judge_action(k, t, said):
    if k in ("net", "dns"):
        ok = bool(NET_WORDS.search(said))
        return {"level": "INFO" if ok else "HIGH", "what": "tried to reach the network (blocked)" + ("" if ok else ", and nothing in the description or disclosure mentions network use")}
    if k == "proc":
        ok = bool(PROC_WORDS.search(said))
        return {"level": "INFO" if ok else "MEDIUM", "what": "started a subprocess" + ("" if ok else ", not mentioned in description or disclosure")}
    if k == "thread":
        return {"level": "MEDIUM", "what": "left a background thread running at the end of the run; anything it does later is not observed"}
    if k == "native":
        return {"level": "HIGH", "what": "loaded native code (ctypes); audit hooks cannot see inside it, so this run is incomplete"}
    return None


def _registration_findings(result, manifest):
    reg, out = result["registered"], []
    for kind, key, alt in (("tools", "provides_tools", "tools"), ("hooks", "provides_hooks", "hooks")):
        declared = set(manifest.get(key) or []) | set(manifest.get(alt) or [])
        extra = sorted(set(reg.get(kind, [])) - declared)
        if extra:
            out.append({"level": "MEDIUM", "what": f"registered {kind} not listed in {key}: {', '.join(extra)}",
                        "phase": "register", "target": ""})
    for e in result["errors"]:
        out.append({"level": "INFO", "what": "error: " + e["error"], "phase": e["phase"], "target": ""})
    return out


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def _clean(x) -> str:
    return _CTRL.sub("?", str(x))


def render(name: str, result: dict, fs: list[dict]) -> str:
    n = {lv: sum(1 for f in fs if f["level"] == lv) for lv in ("HIGH", "MEDIUM", "INFO")}
    lines = [f"Taster: {name}", f"Observed in this run: {n['HIGH']} high, {n['MEDIUM']} medium, {n['INFO']} info. "
             "This is what happened once in a locked box, not a safety verdict.", f"Run ended: {result['ended']}", ""]
    reg = result["registered"]
    lines.append("Registered: " + "; ".join(f"{k}={','.join(v) or '-'}" for k, v in reg.items() if k != "other") or "nothing")
    lines.append("")
    for f in fs:
        tgt = f" [{f['target'].replace(result['home'], '~')}]" if f["target"] else ""
        lines.append(f"{f['level']:<6} {f['phase']:<14} {f['what']}{tgt}")
    if not fs:
        lines.append("No behavior beyond the declared surface was observed in this run.")
    lines += ["", "Not covered: code paths that depend on time, network replies, or a real wallet; native code."]
    return _clean("\n".join(lines)).replace("?\n", "\n") if False else "\n".join(_clean(l) for l in lines)


def _clean_deep(x):
    """Strip control and bidi characters from every string in a nested structure."""
    if isinstance(x, str):
        return _clean(x)
    if isinstance(x, list):
        return [_clean_deep(i) for i in x]
    if isinstance(x, dict):
        return {_clean(str(k)): _clean_deep(v) for k, v in x.items()}
    return x
