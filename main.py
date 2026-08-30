#!/usr/bin/env python3
"""Aegis Workbench entry point."""

import json
import sys
from pathlib import Path

from aegis.cli import Shell
from aegis.scope import ScopeError


def load_config() -> dict:
    path = Path("config.json")
    if not path.exists():
        example = Path("config.example.json")
        if example.exists():
            path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            print(f"Created config.json from example — review it, then re-run.")
        else:
            print("config.json missing and no config.example.json found.")
        sys.exit(1)
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    config = load_config()
    try:
        shell = Shell(config)
    except ScopeError as exc:
        print(f"[SCOPE] {exc}")
        return 2
    shell.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
