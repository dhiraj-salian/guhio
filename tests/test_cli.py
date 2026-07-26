import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from guhio import __version__
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


def test_exec_uses_unlock_session(tmp_path):
    vault_path = tmp_path / "vault.json"
    env = {**os.environ, "GUHIO_MASTER_PASSWORD": "master"}
    init = run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    assert init.returncode == 0

    add = run_cli(
        ["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "secret"]
    )
    assert add.returncode == 0

    unlock = run_cli(["--vault", str(vault_path), "unlock"], env=env)
    assert unlock.returncode == 0
    token_line = unlock.stdout.strip().splitlines()[0]
    assert token_line.startswith("export GUHIO_SESSION=")
    session_token = token_line.split("=", 1)[1]

    exec_env = {**os.environ, "GUHIO_SESSION": session_token}
    exec_result = run_cli(
        [
            "--vault",
            str(vault_path),
            "exec",
            "--with",
            "github:GITHUB_TOKEN",
            "--",
            sys.executable,
            "-c",
            "import os; print(os.environ['GITHUB_TOKEN'])",
        ],
        env=exec_env,
    )
    assert exec_result.returncode == 0
    assert exec_result.stdout.strip() == "secret"


def test_lock_clears_session(tmp_path):
    vault_path = tmp_path / "vault.json"
    env = {**os.environ, "GUHIO_MASTER_PASSWORD": "master"}
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    run_cli(["--vault", str(vault_path), "unlock"], env=env)

    lock = run_cli(["--vault", str(vault_path), "lock"])
    assert lock.returncode == 0

    # After locking, exec with no password source should fail rather than run.
    exec_result = run_cli(
        ["--vault", str(vault_path), "exec", "--with", "github:GITHUB_TOKEN", "--", "echo", "x"]
    )
    assert exec_result.returncode != 0


def test_exec_password_flag_after_subcommand(tmp_path):
    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    run_cli(
        ["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "secret"]
    )

    exec_result = run_cli(
        [
            "--vault",
            str(vault_path),
            "exec",
            "--password",
            "master",
            "--with",
            "github:GITHUB_TOKEN",
            "--",
            sys.executable,
            "-c",
            "import os; print(os.environ['GITHUB_TOKEN'])",
        ]
    )
    assert exec_result.returncode == 0
    assert exec_result.stdout.strip() == "secret"


def test_exec_does_not_leak_master_password_to_child(tmp_path):
    vault_path = tmp_path / "vault.json"
    env = {**os.environ, "GUHIO_MASTER_PASSWORD": "master"}
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")

    unlock = run_cli(["--vault", str(vault_path), "unlock"], env=env)
    assert unlock.returncode == 0
    token_line = unlock.stdout.strip().splitlines()[0]
    session_token = token_line.split("=", 1)[1]

    session_env = {k: v for k, v in os.environ.items() if k != "GUHIO_MASTER_PASSWORD"}
    session_env["GUHIO_SESSION"] = session_token

    add = run_cli(
        ["--vault", str(vault_path), "add", "github", "--value", "secret"],
        env=session_env,
    )
    assert add.returncode == 0

    exec_result = run_cli(
        [
            "--vault",
            str(vault_path),
            "exec",
            "--with",
            "github:GITHUB_TOKEN",
            "--",
            sys.executable,
            "-c",
            "import os; print('SEEN:', os.environ.get('GUHIO_MASTER_PASSWORD', 'none'))",
        ],
        env=session_env,
    )
    assert exec_result.returncode == 0
    assert "SEEN: none" in exec_result.stdout


def test_exec_expands_env_placeholders(tmp_path):
    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    run_cli(
        ["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "secret"]
    )

    exec_result = run_cli(
        [
            "--vault",
            str(vault_path),
            "exec",
            "--password",
            "master",
            "--expand",
            "--with",
            "github:GITHUB_TOKEN",
            "--",
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            "value=$GITHUB_TOKEN",
        ]
    )
    assert exec_result.returncode == 0
    assert exec_result.stdout.strip() == "value=secret"


def test_parser_rejects_unknown_command():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["unknown"])


def test_dashboard_port_from_env(monkeypatch):
    monkeypatch.setenv("GUHIO_PORT", "8080")
    parser = build_parser()
    args = parser.parse_args(["dashboard"])
    assert args.port == 8080


def test_dashboard_host_from_env(monkeypatch):
    monkeypatch.setenv("GUHIO_HOST", "0.0.0.0")
    parser = build_parser()
    args = parser.parse_args(["dashboard"])
    assert args.host == "0.0.0.0"


def test_dashboard_port_flag_overrides_env(monkeypatch):
    monkeypatch.setenv("GUHIO_PORT", "8080")
    parser = build_parser()
    args = parser.parse_args(["dashboard", "--port", "9000"])
    assert args.port == 9000


def test_version_flag_prints_version():
    result = run_cli(["--version"])
    assert result.returncode == 0
    assert f"guhio {__version__}" in result.stdout


def test_version_command_prints_version():
    result = run_cli(["version"])
    assert result.returncode == 0
    assert f"guhio {__version__}" in result.stdout


def test_keyboard_interrupt_is_handled_gracefully(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["guhio", "--vault", "/tmp/guhio-test-vault.json", "init"])
    monkeypatch.setattr("guhio.cli.cmd_init", lambda args: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 130
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err


def test_errors_do_not_include_tracebacks(tmp_path):
    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    bad = run_cli(["--vault", str(vault_path), "--password", "wrong", "unlock"])
    assert bad.returncode == 1
    assert "Traceback" not in bad.stdout + bad.stderr


def test_init_with_piped_input_does_not_warn_about_echo(tmp_path):
    vault_path = tmp_path / "vault.json"
    result = run_cli(["--vault", str(vault_path), "init"], input_text="pass\npass\n")
    assert result.returncode == 0
    assert "Warning: Password input may be echoed" not in result.stderr


# --- Security hardening tests ---


def test_exec_rejects_invalid_env_var_name(tmp_path):
    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    run_cli(
        ["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "secret"]
    )

    result = run_cli(
        [
            "--vault", str(vault_path), "--password", "master",
            "exec", "--with", "github:INVALID-NAME", "--", "echo", "x",
        ]
    )
    assert result.returncode != 0
    assert "Invalid environment variable name" in result.stderr


def test_exec_accepts_valid_env_var_name(tmp_path):
    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    run_cli(
        ["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "secret"]
    )

    result = run_cli(
        [
            "--vault", str(vault_path), "--password", "master",
            "exec", "--with", "github:GITHUB_TOKEN", "--",
            sys.executable, "-c", "import os; print(os.environ['GITHUB_TOKEN'])",
        ]
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "secret"


def test_audit_log_records_events(tmp_path):
    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    run_cli(
        ["--vault", str(vault_path), "--password", "master", "add", "github", "--value", "ghp_secret"]
    )

    audit_path = vault_path.parent / "audit.log"
    assert audit_path.exists()
    log_content = audit_path.read_text()
    assert "vault_created" in log_content
    assert "credential_added" in log_content
    assert "github" in log_content
    # The credential value and password must never appear in the audit log.
    assert "ghp_secret" not in log_content
    assert "master" not in log_content


def test_audit_log_has_restrictive_permissions(tmp_path):
    import os
    if os.name != "posix":
        pytest.skip("file permissions are POSIX-only")

    vault_path = tmp_path / "vault.json"
    run_cli(["--vault", str(vault_path), "init"], input_text="master\nmaster\n")
    audit_path = vault_path.parent / "audit.log"
    assert audit_path.exists()
    mode = audit_path.stat().st_mode & 0o777
    assert mode == 0o600
