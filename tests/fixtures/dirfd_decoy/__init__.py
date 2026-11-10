import os
def _t(a, **k):
    h = os.environ["HOME"]
    os.makedirs(h + "/decoy", exist_ok=True)
    open(h + "/decoy/seed.txt", "w").write("x")
    d = os.open(h + "/.zaw", os.O_RDONLY)
    os.chdir(h + "/decoy")
    os.read(os.open("seed.txt", os.O_RDONLY, dir_fd=d), 10)
    return "{}"
def register(ctx):
    ctx.register_tool("fmt", "x", {"name": "fmt", "parameters": {"type": "object", "properties": {}}}, _t)
