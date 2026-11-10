"""The locked box: fake home with canary files, network denied, writes confined, one child run."""
from __future__ import annotations
import json, os, signal, threading, os, shutil, subprocess, sys, tempfile
from pathlib import Path

CHILD = Path(__file__).with_name("probe_child.py")
CANARY_FILES = {
    ".zaw/wallet.json": '{"taster_canary": true, "note": "fake wallet"}',
    ".zaw/seed.txt": "taster canary seed phrase not real",
    ".config/zcash/wallet.dat": "taster-canary",
    ".ssh/id_ed25519": "-----TASTER CANARY KEY-----",
    ".env": "OPENAI_API_KEY=taster-canary",
    ".hermes/.env": "ANTHROPIC_API_KEY=taster-canary",
}
CANARY_ENV = {"ZEC_SEED_PHRASE": "taster-canary", "ZAW_WALLET_PATH": "~/.zaw",
              "OPENAI_API_KEY": "taster-canary", "ANTHROPIC_API_KEY": "taster-canary",
              "SHIELDED_ADDRESS": "u1tastercanary"}
WALLET_HINTS = ("zaw", "zcash", "seed", "wallet", "ZEC", "SHIELDED")


def build_home(root: Path) -> list[str]:
    for rel, text in CANARY_FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return [str((root / rel).resolve()) for rel in CANARY_FILES]


_UNSAFE = set('"\\()') | {chr(c) for c in range(32)} | {chr(127)}


def _safe(p: str) -> str:
    if any(c in _UNSAFE for c in p):
        raise ValueError("path contains characters that are not allowed in the box profile: " + repr(p)[:80])
    return p


def profile(home: Path, allow_read: list[str]) -> str:
    """Network denied, writes confined to the fake home, reads of the real HOME denied except what Python and the plugin need."""
    h = _safe(str(home.resolve()))
    real = _safe(str(Path.home().resolve()))
    allow = "".join(f'(allow file-read* (subpath "{_safe(p)}"))' for p in allow_read)
    return ("(version 1)(allow default)(deny network*)"
            f'(deny file-write* (require-not (require-any (subpath "{h}") (subpath "/dev"))))'
            f'(deny file-read* (subpath "{real}")){allow}')


def python_for_child() -> str:
    venv = Path.home() / ".hermes/hermes-agent/venv/bin/python"
    return str(venv) if venv.exists() and "hermes" not in sys.executable else sys.executable


def _read_allow(py: str, plugin_dir: Path) -> list[str]:
    paths = {str(CHILD.resolve().parent), str(plugin_dir.resolve()), str(Path(py).resolve().parent.parent), str(Path(py).parent.parent)}
    for extra in (Path.home() / ".local/share/uv/python", Path.home() / ".pyenv", Path.home() / ".local/share/uv/tools"):
        if extra.exists():
            paths.add(str(extra)); paths.add(str(extra.resolve()))
    hermes = Path.home() / ".hermes/hermes-agent"
    if hermes.exists():
        paths.add(str(hermes.resolve()))
    return sorted(paths)


def _collect(fd: int, sink: dict) -> None:
    with os.fdopen(fd, "rb") as f:
        for line in f:
            if not line.endswith(b"\n"):
                sink["tampered"] = True  # unterminated line before EOF
            try:
                m = json.loads(line)
            except ValueError:
                sink["tampered"] = True  # our child only writes whole JSON lines
                continue
            if sink["final"] is not None:
                sink["tampered"] = True  # anything after the final line is not ours
            if isinstance(m, dict) and set(m) == {"final"} and isinstance(m["final"], dict):
                if sink["final"] is not None:
                    sink["tampered"] = True  # two finals: one was forged
                sink["final"] = m["final"]
            elif isinstance(m, dict) and set(m) == {"phase", "kind", "target"}:
                sink["events"].append({k: str(m[k])[:300] for k in ("phase", "kind", "target")})
            else:
                sink["tampered"] = True  # unexpected shape


def taste(plugin_dir: str, timeout: int = 60, keep: bool = False) -> dict:
    """Run the plugin once in the box. Events arrive over a pipe the plugin cannot rewrite after the fact."""
    work = Path(tempfile.mkdtemp(prefix="taster-")).resolve()
    home = work / "home"
    canaries = build_home(home)
    env = {"HOME": str(home), "HERMES_HOME": str(home / ".hermes"), "PATH": "/usr/bin:/bin",
           "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(work), **{k: v.replace("~", str(home)) for k, v in CANARY_ENV.items()}}
    py = python_for_child()
    rfd, wfd = os.pipe()
    cmd = ["sandbox-exec", "-p", profile(home, _read_allow(py, Path(plugin_dir))), py, "-I", str(CHILD),
           str(Path(plugin_dir).resolve()), "-", str(wfd)]
    sink = {"events": [], "final": None, "tampered": False}
    t = threading.Thread(target=_collect, args=(rfd, sink), daemon=True)
    t.start()
    ended = "ok"
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                         pass_fds=(wfd,), start_new_session=True)
    os.close(wfd)
    try:
        _, err = p.communicate(timeout=timeout)
        ended = "ok" if p.returncode == 0 else f"child exit {p.returncode}: {(err or '').strip()[-160:]}"
    except subprocess.TimeoutExpired:
        ended = f"timeout after {timeout}s"
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    t.join(5)
    final = sink["final"]
    if final is None and ended == "ok":
        ended = "no result received from the box"
    if sink["tampered"]:
        ended = "result stream was tampered with (extra lines after or duplicate final result)"
    reg = final.get("registered", {}) if final else {}
    errs = final.get("errors", []) if final else []
    if not keep:
        shutil.rmtree(work, ignore_errors=True)
    return {"canary_files": canaries, "canary_env": sorted(CANARY_ENV), "home": str(home), "ended": ended,
            "registered": reg if isinstance(reg, dict) else {}, "events": sink["events"],
            "errors": [{"phase": str(e.get("phase", ""))[:40], "error": str(e.get("error", ""))[:200]} for e in errs if isinstance(e, dict)]}
