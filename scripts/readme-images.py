"""Build the README stills from real Taster runs. Needs macOS and Google Chrome."""
import html, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "readme"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SEV = {"HIGH": "#c62828", "MEDIUM": "#b26a00", "INFO": "#5b6470"}

PAGE = """<!doctype html><meta charset=utf-8><style>
html,body{{margin:0;background:#f4f1ea}}
.card{{margin:24px;width:{w}px;background:#fffdf8;border:1px solid #d9d3c4;border-radius:12px;box-shadow:0 2px 10px #0002;overflow:hidden;font:15px/1.5 ui-monospace,Menlo,monospace;color:#1f2328}}
.bar{{padding:10px 16px;background:#ebe6d8;border-bottom:1px solid #d9d3c4;font-weight:600}}
pre{{margin:0;padding:16px;white-space:pre-wrap;word-break:break-word}}
</style><div class=card><div class=bar>$ {cmd}</div><pre>{body}</pre></div>"""


def colour(line):
    esc = html.escape(line)
    for tag, c in SEV.items():
        if line.startswith(tag):
            return f'<b style="color:{c}">{tag}</b>' + esc[len(tag):]
    return esc


def shot(name, plugin, width=1000):
    run = subprocess.run([sys.executable, "-m", "taster", plugin], cwd=ROOT, capture_output=True, text=True)
    lines = [l for l in run.stdout.splitlines()]
    page = PAGE.format(w=width, cmd=f"python3 -m taster {plugin}", body="\n".join(colour(l) for l in lines))
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "p.html"
        f.write_text(page)
        height = 120 + 25 * len(lines) + 40
        subprocess.run([CHROME, "--headless=new", "--hide-scrollbars", f"--window-size={width + 48},{height}",
                        "--force-device-scale-factor=2", f"--screenshot={OUT / (name + '.png')}", f.as_uri()],
                       check=True, capture_output=True)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    shot("dishonest", "tests/fixtures/dishonest")
    shot("honest", "tests/fixtures/honest")
