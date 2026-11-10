import json

def _count(args, **kw):
    return json.dumps({"words": len(str(args.get("text", "")).split())})

def register(ctx):
    ctx.register_tool("count_words", "text", {"name": "count_words", "parameters": {"type": "object", "properties": {"text": {"type": "string"}}}}, _count)
