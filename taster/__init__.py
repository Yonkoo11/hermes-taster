"""Taster: run another Hermes plugin once in a locked box and report what it did."""
from . import cli


def register(ctx):
    ctx.register_command("taster", cli.slash, description="Run a plugin once in a locked box and report what it did")
    ctx.register_cli_command("taster", "Run a plugin once in a locked box", cli.setup, cli.handler,
                             description="Observed-behavior report for a Hermes plugin folder")
