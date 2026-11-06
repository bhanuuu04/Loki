"""
Direct module execution entry point for Loki (`python -m loki`).
"""

import sys
from loki.cli.main import cli_entrypoint

if __name__ == "__main__":
    cli_entrypoint()
