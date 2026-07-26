import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from guhio.cli import build_parser, main


def run_cli(args, env=None, input_text=None):
    """Run the CLI in a subprocess and return output."""
    cmd = [sys.executable, "-m", "guhio.cli"] + args
    result = subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        env=env,
    )
    return result


def test_init_creates_vault(tmp_path):
    vault_path = tmp_path / "vault.json"
    result = run_cli(["--vault", str(vault_path), "init"], input_text="pass\npass\n")
    assert result.returncode == 0
    assert vault_path.exists()


def test_init_password_mismatch(tmp_path):
    vault_path = tmp_path / "vault.json"
    result = run_cli(["--vault", str(vault_path), "init"], input_text="pass\nwrong\n")
    assert result.returncode == 1


def test_add_and_list(tmp_path):
    vault_path = tmp_path / "vault.json"
    env = {**os.environ, "GUHIO_MASTER_PASSWORD": "master"}
    init = run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    assert init.returncode == 0

    add = run_cli(
        ["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "token"]
    )
    assert add.returncode == 0

    lst = run_cli(["--vault", str(vault_path), "--password", "master", "list"])
    assert lst.returncode == 0
    assert "github" in lst.stdout


def test_get_reveals_value(tmp_path):
    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    run_cli(["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "secret"])

    get = run_cli(["--vault", str(vault_path), "--password", "master", "get", "github"])
    assert get.returncode == 0
    assert get.stdout.strip() == "secret"


def test_exec_injects_env_var(tmp_path):
    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    run_cli(
        ["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "secret-token"]
    )

    exec_result = run_cli(
        [
            "--vault",
            str(vault_path),
            "--password",
            "master",
            "exec",
            "--with",
            "github:GITHUB_TOKEN",
            "--",
            sys.executable,
            "-c",
            "import os; print(os.environ['GITHUB_TOKEN'])",
        ]
    )
    assert exec_result.returncode == 0
    assert exec_result.stdout.strip() == "secret-token"


def test_parser_rejects_unknown_command():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["unknown"])
