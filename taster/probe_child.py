"""Runs INSIDE the box. Loads one plugin, runs register(ctx), then calls each tool and hook once.

usage: python probe_child.py <plugin_dir> <out.json>
Every event comes from sys.addaudithook or the recording os.environ. Native code (ctypes) can
slip past audit hooks, so ctypes use is itself reported.
"""
import importlib.util, json, os, signal, sys, sysconfig, types
from collections.abc import MutableMapping

PLUGIN, OUT = sys.argv[1], sys.argv[2]
_open = open
EVENTS, REG, ERRORS = [], {"tools": [], "hooks": [], "commands": [], "cli": [], "other": []}, []
PHASE = ["import"]
QUIET = [True]  # until the hook is armed
SKIP = tuple({os.path.realpath(p) for p in (sys.prefix, sys.base_prefix,
             sysconfig.get_path("stdlib"), sysconfig.get_path("purelib"), sysconfig.get_path("platlib")) if p})
KINDS = {"socket.connect": "net", "socket.getaddrinfo": "dns", "subprocess.Popen": "proc",
         "os.system": "proc", "os.exec": "proc", "os.spawn": "proc", "os.posix_spawn": "proc",
         "ctypes.dlopen": "native", "ctypes.call_function": "native", "os.remove": "write",
         "os.rename": "write", "os.link": "write", "os.symlink": "write", "os.mkdir": "write", "shutil.rmtree": "write"}


def _ident(p):
    try:
        st = os.stat(p); return (st.st_dev, st.st_ino)
    except (OSError, TypeError, ValueError):
        return None


# identity of every bait file at start, so a hardlink or renamed copy still resolves to the canary
CANARY_IDS = {}
for _r, _d, _fs in os.walk(os.environ.get("HOME", "/nonexistent")):
    for _f in _fs:
        _p = os.path.realpath(os.path.join(_r, _f)); CANARY_IDS[_ident(_p)] = _p
FAKE_HOME = os.path.realpath(os.environ.get("HOME", "/nonexistent"))


CANARY_BASE = {}
for _p in CANARY_IDS.values():
    CANARY_BASE.setdefault(os.path.basename(_p), _p)


def _canary_alias(p):
    if not isinstance(p, (str, bytes, os.PathLike)):
        return None
    hit = CANARY_IDS.get(_ident(p))
    if hit:
        return hit
    q = os.fsdecode(p)
    if not os.path.isabs(q):
        # relative path: may be opened with dir_fd, which the hook cannot resolve, so match by name
        return CANARY_BASE.get(os.path.basename(q))
    return None


def _skip_path(p):
    rp = os.path.realpath(p) if isinstance(p, (str, bytes)) else ""
    rp = rp.decode() if isinstance(rp, bytes) else rp
    if rp.startswith(FAKE_HOME + "/"):
        return False  # nothing inside the fake home is ever ignored
    return (not rp) or rp.startswith(SKIP) or rp.endswith((".pyc", ".so", ".dylib")) \
        or rp.startswith(os.path.realpath(PLUGIN)) or rp.startswith("/dev/") or "/__pycache__" in rp


_WRITE, _DUMPS, _FD = os.write, json.dumps, int(sys.argv[3])
sys.argv[:] = sys.argv[:1]  # the plugin should not find the pipe fd in argv


def _emit(ev):
    """Send each event to the parent the moment it happens, so later plugin code cannot erase it."""
    EVENTS.append(ev)
    try:
        _WRITE(_FD, (_DUMPS(ev) + "\n").encode())
    except Exception:
        pass


def _target(name, args):
    """Readable target: the host:port, the path, or the command, not the raw audit tuple."""
    try:
        if name == "socket.connect":
            return "connect " + ":".join(str(x) for x in args[1])
        if name == "socket.getaddrinfo":
            return f"dns {args[0]}:{args[1]}"
        if name.startswith(("os.", "shutil.")) and args and isinstance(args[0], (str, bytes, os.PathLike)):
            return os.path.realpath(os.fsdecode(args[0]))
        return name + " " + str(args[0] if len(args) == 1 else args)[:200]
    except Exception:
        return name


def _audit(name, args):
    if QUIET[0]:
        return
    kind = KINDS.get(name)
    if name == "open":
        mode = str(args[1] or "r")
        alias = _canary_alias(args[0])
        if alias or not _skip_path(args[0]):
            _emit({"phase": PHASE[0], "kind": "write" if set(mode) & set("wax+") else "read",
                   "target": alias or (os.path.realpath(args[0]) if isinstance(args[0], str) else str(args[0]))})
    elif kind:
        tgt = _target(name, args)
        if kind == "write" and _skip_path(tgt):
            return
        _emit({"phase": PHASE[0], "kind": kind, "target": tgt})


class RecEnviron(MutableMapping):
    """Environment view with a private store: every way to read it records an event.
    Not a dict subclass, so dict.get(env, k) and similar bypasses raise instead of leaking."""

    def __init__(self, data):
        object.__setattr__(self, "_d", dict(data))

    def _rec(self, k):
        if not QUIET[0]:
            _emit({"phase": PHASE[0], "kind": "env", "target": os.fsdecode(k) if isinstance(k, bytes) else str(k)})

    def _all(self, what):
        if not QUIET[0]:
            _emit({"phase": PHASE[0], "kind": "envall", "target": what})

    def __getitem__(self, k):
        self._rec(k); return self._d[k]

    def __setitem__(self, k, v):
        self._d[k] = v

    def __delitem__(self, k):
        del self._d[k]

    def __contains__(self, k):
        self._rec(k); return k in self._d

    def get(self, k, d=None):
        self._rec(k); return self._d.get(k, d)

    def pop(self, k, *d):
        self._rec(k); return self._d.pop(k, *d)

    def setdefault(self, k, d=None):
        self._rec(k); return self._d.setdefault(k, d)

    def popitem(self):
        self._all("popitem"); return self._d.popitem()

    def __len__(self):
        return len(self._d)

    def __iter__(self):
        self._all("iter"); return iter(list(self._d))

    def items(self):
        self._all("items"); return list(self._d.items())

    def keys(self):
        self._all("keys"); return list(self._d)

    def values(self):
        self._all("values"); return list(self._d.values())

    def copy(self):
        self._all("copy"); return dict(self._d)

    def __or__(self, o):
        self._all("or"); return {**self._d, **dict(o)}

    __ror__ = __or__

    def __repr__(self):
        self._all("repr"); return repr(self._d)

    __str__ = __repr__

    def __reduce__(self):
        self._all("reduce"); return (dict, (dict(self._d),))

    def __eq__(self, o):
        self._all("eq"); return self._d == (o._d if isinstance(o, RecEnviron) else o)

    __hash__ = None


class RecCtx:
    manifest = types.SimpleNamespace(name="plugin-under-taste")
    plugin_id = "plugin-under-taste"

    def register_tool(self, name, toolset=None, schema=None, handler=None, *a, **k):
        REG["tools"].append((name, handler))

    def register_hook(self, name, cb):
        REG["hooks"].append((name, cb))

    def register_command(self, name, handler=None, *a, **k):
        REG["commands"].append(name)

    def register_cli_command(self, name, *a, **k):
        REG["cli"].append(name)

    def __getattr__(self, n):
        return lambda *a, **k: REG["other"].append(n)


class _Timeout(Exception):
    pass


def _guard(label, fn, *a, **k):
    PHASE[0] = label
    def alarm(*_): raise _Timeout()
    signal.signal(signal.SIGALRM, alarm); signal.setitimer(signal.ITIMER_REAL, 5)
    try:
        fn(*a, **k)
    except BaseException as e:  # a plugin may raise anything, including SystemExit
        ERRORS.append({"phase": label, "error": type(e).__name__ + ": " + str(e)[:160]})
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def _load():
    pdir = os.path.realpath(PLUGIN)
    spec = importlib.util.spec_from_file_location("plugin_under_taste", os.path.join(pdir, "__init__.py"),
                                                  submodule_search_locations=[pdir])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["plugin_under_taste"] = mod
    spec.loader.exec_module(mod)
    return mod


def _exercise():
    for name, handler in list(REG["tools"]):
        if callable(handler):
            _guard("tool:" + name, handler, {})
    for name, cb in list(REG["hooks"]):
        kw = {"tool_name": "terminal", "args": {"command": "ls"}, "session_id": "taster", "result": "ok"}
        _guard("hook:" + name, lambda c=cb, kw=kw: c(**kw))


def main():
    import posix
    os.environ = RecEnviron(os.environ)
    os.environb = RecEnviron(os.environb)  # bytes view: same data, must be recorded too
    posix.environ = RecEnviron(posix.environ)
    QUIET[0] = False
    sys.addaudithook(_audit)
    holder = {}
    _guard("import", lambda: holder.update(mod=_load()))
    if "mod" in holder and hasattr(holder["mod"], "register"):
        _guard("register", holder["mod"].register, RecCtx())
    elif "mod" in holder:
        ERRORS.append({"phase": "register", "error": "no register(ctx) function"})
    _exercise()
    import threading
    left = [t.name for t in threading.enumerate() if t is not threading.main_thread()]
    if left:
        _emit({"phase": "end", "kind": "thread", "target": ", ".join(left)[:200]})
    QUIET[0] = True
    out = {"registered": {k: [x[0] if isinstance(x, tuple) else x for x in v] for k, v in REG.items()},
           "events": EVENTS, "errors": ERRORS}
    _WRITE(_FD, (_DUMPS({"final": {"registered": out["registered"], "errors": ERRORS}}) + "\n").encode())
    os._exit(0)  # a thread the plugin left running must not act after the result is sent


main()
