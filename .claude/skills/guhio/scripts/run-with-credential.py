#!/usr/bin/env python3
"""Run a command with Guhio credentials injected as environment variables."""

import argparse
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
    parser = argparse.ArgumentParser(
        description="Run a command with Guhio credentials injected as environment variables."
    )
    parser.add_argument(
        "--with",
        dest="with_",
        action="append",
        required=True,
        metavar="NAME:ENV_VAR",
        help="Credential name and the environment variable to inject it into",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command and arguments to run",
    )
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("Error: no command provided.", file=sys.stderr)
        return 1

    guhio_cmd = _find_guhio_command()
    guhio_cmd += ["exec"]
    for mapping in args.with_:
        guhio_cmd += ["--with", mapping]
    guhio_cmd += ["--"] + command

    result = subprocess.run(guhio_cmd, env=os.environ.copy())
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
