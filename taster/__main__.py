import argparse, sys
from . import cli

p = argparse.ArgumentParser(prog="python -m taster", description="Run a Hermes plugin once in a locked box and report what it did.")
cli.setup(p)
sys.exit(cli.handler(p.parse_args()))
