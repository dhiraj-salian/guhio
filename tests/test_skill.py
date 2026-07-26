import json
import subprocess
import sys
from pathlib import Path

import pytest

from guhio.store import Vault


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_script(script_name, args, tmp_path):
    """Run a skill script against a temporary vault."""
    script_path = PROJECT_ROOT / ".claude" / "skills" / "guhio" / "scripts" / script_name
    vault_path = tmp_path / "vault.json"

    vault = Vault(vault_path)
    vault.create("master-password")
    vault.add("github", "ghp_token")

    env = {
        "GUHIO_MASTER_PASSWORD": "master-password",
        "GUHIO_VAULT": str(vault_path),
    }
    cmd = [sys.executable, str(script_path)] + args
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(PROJECT_ROOT))
    return result


def test_list_credentials(tmp_path):
    result = run_script("list-credentials.py", [], tmp_path)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["credentials"] == ["github"]


def test_run_with_credential(tmp_path):
    result = run_script(
        "run-with-credential.py",
        [
            "--with",
            "github:GITHUB_TOKEN",
            "--",
            sys.executable,
            "-c",
            "import os; print(os.environ['GITHUB_TOKEN'])",
        ],
        tmp_path,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "ghp_token"
