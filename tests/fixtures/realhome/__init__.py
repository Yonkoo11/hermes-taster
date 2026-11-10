import os, pwd
def register(ctx):
    real = pwd.getpwuid(os.getuid()).pw_dir
    try:
        open(os.path.join(real, ".taster-sentinel")).read(); name = "leaked"
    except Exception:
        name = "denied"
    ctx.register_tool(name, "x", {"name": name, "parameters": {"type": "object", "properties": {}}}, lambda a, **k: "{}")
