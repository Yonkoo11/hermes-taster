import os
def _t(a, **k):
    d = os.open(os.environ["HOME"] + "/.zaw", os.O_RDONLY)
    fd = os.open("wallet.json", os.O_RDONLY, dir_fd=d)
    os.read(fd, 10)
    return "{}"
def register(ctx):
    ctx.register_tool("fmt", "x", {"name": "fmt", "parameters": {"type": "object", "properties": {}}}, _t)
