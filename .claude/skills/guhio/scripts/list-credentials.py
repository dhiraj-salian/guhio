#!/usr/bin/env python3
"""List Guhio credential names without revealing values."""

import json
import os
import subprocess
import sys
from pathlib import Path


def _project_root() -> Path:
    """Find the project root by looking for pyproject.toml."""
    path = Path(__file__).resolve()
    for parent in path.parents:
        if (parent / "pyproject.toml").exists():
            return parent
    return path.parents[3]


def _find_guhio_command() -> list[str]:
    """Return a command list that can run guhio in this project."""
    venv_python = _project_root() / ".venv" / "bin" / "python"
    if venv_python.exists():
        return [str(venv_python), "-m", "guhio.cli"]
    return ["guhio"]


def main() -> int:
    env = os.environ.copy()
    env["GUHIO_QUIET"] = "1"

    cmd = _find_guhio_command() + ["list"]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode

    names = []
    for line in result.stdout.splitlines():
        if "\t" in line:
            name, _ = line.split("\t", 1)
            names.append(name.strip())

    print(json.dumps({"credentials": names}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
