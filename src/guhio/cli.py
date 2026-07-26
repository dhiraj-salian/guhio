"""Command-line interface for the password vault."""

import argparse
import getpass
import os
import re
import subprocess
import sys
import warnings
from pathlib import Path

from guhio import __version__
from guhio import audit
from guhio import session as session_store
from guhio.store import (
    EntryNotFoundError,
    InvalidPasswordError,
    Vault,
    VaultError,
    VaultNotFoundError,
)


def _supports_color(stream) -> bool:
    """Return True if the stream supports ANSI color codes."""
    return hasattr(stream, "isatty") and stream.isatty()


def _style(text: str, color: str, bold: bool = False, stream=sys.stderr) -> str:
    """Apply ANSI color/style to text when the stream supports it."""
    if not _supports_color(stream):
        return text
    codes = [color]
    if bold:
        codes.append("1")
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def _error(message: str) -> None:
    """Print a user-facing error message to stderr."""
    prefix = _style("error:", "31", bold=True)
    print(f"{prefix} {message}", file=sys.stderr)


def _info(message: str) -> None:
    """Print an informational message to stderr."""
    prefix = _style("info:", "34", bold=True)
    print(f"{prefix} {message}", file=sys.stderr)


def _prompt_password(prompt: str = "Master password: ") -> str:
    """Prompt for a password without echoing on a TTY, or read from stdin."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline().rstrip("\n")


def _prompt_new_password() -> str:
    """Prompt for a new master password twice to avoid typos."""
    if sys.stdin.isatty():
        first = getpass.getpass("Set master password: ")
        second = getpass.getpass("Confirm master password: ")
    else:
        first = sys.stdin.readline().rstrip("\n")
        second = sys.stdin.readline().rstrip("\n")
    if first != second:
        _error("Passwords do not match.")
        sys.exit(1)
    if not first:
        _error("Master password cannot be empty.")
        sys.exit(1)
    return first


def _read_env_password() -> str | None:
    """Read the master password from the environment if available."""
    return os.environ.get("GUHIO_MASTER_PASSWORD")


def _get_password_for_unlock(args, vault: Vault) -> str:
    """Determine the master password for unlocking an existing vault."""
    session_token = os.environ.get("GUHIO_SESSION")
    if session_token:
        password = session_store.load_session_password(vault.path, session_token)
        if password is not None:
            return password

    env_password = _read_env_password()
    if env_password is not None:
        return env_password
    if args.password:
        return args.password
    return _prompt_password()


def cmd_init(args) -> None:
    """Create a new vault."""
    vault = Vault(args.vault)
    if vault.exists():
        _error(f"Vault already exists at {vault.path}")
        sys.exit(1)
    master_password = _prompt_new_password()
    vault.create(master_password)
    audit.log_event(vault.path, "vault_created")
    print(f"Vault created at {vault.path}")


def cmd_unlock(args) -> None:
    """Unlock the vault and create a session token for subsequent commands."""
    vault = Vault(args.vault)
    password = _get_password_for_unlock(args, vault)
    try:
        vault.unlock(password)
    except InvalidPasswordError as exc:
        audit.log_event(vault.path, "unlock_failed")
        _error(exc)
        sys.exit(1)

    audit.log_event(vault.path, "unlock_succeeded")
    token = session_store.save_session(vault.path, password)
    print(f"export GUHIO_SESSION={token}")
    _info("Vault unlocked.")


def cmd_lock(args) -> None:
    """Lock the vault by clearing any active CLI session."""
    vault = Vault(args.vault)
    session_store.clear_session(vault.path)
    audit.log_event(vault.path, "vault_locked")
    _info("Vault locked.")


def cmd_add(args) -> None:
    """Add a new credential to the vault."""
    vault = Vault(args.vault)
    password = _get_password_for_unlock(args, vault)
    try:
        vault.unlock(password)
    except InvalidPasswordError as exc:
        _error(exc)
        sys.exit(1)

    if args.value:
        value = args.value
    else:
        value = _prompt_password(f"Enter value for '{args.name}': ")
    if not value:
        _error("Credential value cannot be empty.")
        sys.exit(1)

    try:
        vault.add(args.name, value)
    except VaultError as exc:
        _error(exc)
        sys.exit(1)
    audit.log_event(vault.path, "credential_added", name=args.name)
    print(f"Credential '{args.name}' added.")


def cmd_list(args) -> None:
    """List stored credential names."""
    vault = Vault(args.vault)
    password = _get_password_for_unlock(args, vault)
    try:
        vault.unlock(password)
    except InvalidPasswordError as exc:
        _error(exc)
        sys.exit(1)

    entries = vault.list_entries()
    if not entries:
        print("Vault is empty.")
        return
    for entry in entries:
        print(f"{entry.name}\t{entry.created_at.isoformat()}")


def cmd_remove(args) -> None:
    """Remove a credential from the vault."""
    vault = Vault(args.vault)
    password = _get_password_for_unlock(args, vault)
    try:
        vault.unlock(password)
    except InvalidPasswordError as exc:
        _error(exc)
        sys.exit(1)

    try:
        vault.remove(args.name)
    except EntryNotFoundError as exc:
        _error(exc)
        sys.exit(1)
    audit.log_event(vault.path, "credential_removed", name=args.name)
    print(f"Credential '{args.name}' removed.")


def cmd_get(args) -> None:
    """Print a credential value to stdout.

    This subcommand exists for human use and scripts; agents should prefer
    ``exec`` to avoid exposing values in their context.
    """
    vault = Vault(args.vault)
    password = _get_password_for_unlock(args, vault)
    try:
        vault.unlock(password)
    except InvalidPasswordError as exc:
        _error(exc)
        sys.exit(1)

    try:
        value = vault.get(args.name)
    except EntryNotFoundError as exc:
        _error(exc)
        sys.exit(1)
    audit.log_event(vault.path, "credential_revealed", name=args.name)
    print(value)


def _parse_mapping(mapping: str) -> tuple[str, str]:
    """Parse 'name:ENV_VAR' into credential name and environment variable name."""
    if ":" not in mapping:
        return mapping, mapping.upper()
    name, env_var = mapping.split(":", 1)
    return name, env_var


_ENV_VAR_RE = re.compile(r"\$\{(\w+)\}|\$(\w+)")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _expand_vars(text: str, env: dict[str, str]) -> str:
    """Expand $VAR and ${VAR} placeholders using the provided environment."""

    def _repl(match: re.Match[str]) -> str:
        var = match.group(1) or match.group(2)
        return env.get(var, match.group(0))

    return _ENV_VAR_RE.sub(_repl, text)


def cmd_dashboard(args) -> None:
    """Start the local web dashboard."""
    from guhio.dashboard import run_dashboard

    _info(f"Starting Guhio dashboard at http://{args.host}:{args.port}")
    _info("Press Ctrl+C to stop.")
    run_dashboard(host=args.host, port=args.port, debug=args.debug)


def cmd_exec(args) -> None:
    """Run a command with credentials injected as environment variables."""
    vault = Vault(args.vault)
    password = _get_password_for_unlock(args, vault)
    try:
        vault.unlock(password)
    except InvalidPasswordError as exc:
        _error(exc)
        sys.exit(1)

    env = os.environ.copy()
    used_names = []
    for mapping in args.with_:
        name, env_var = _parse_mapping(mapping)
        if not _ENV_NAME_RE.match(env_var):
            _error(f"Invalid environment variable name: '{env_var}'")
            sys.exit(1)
        try:
            env[env_var] = vault.get(name)
        except EntryNotFoundError as exc:
            _error(exc)
            sys.exit(1)
        used_names.append(name)
    audit.log_event(vault.path, "credential_used", names=",".join(used_names))

    # Do not leak the master password or session token to the child process.
    env.pop("GUHIO_MASTER_PASSWORD", None)
    env.pop("GUHIO_SESSION", None)

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        _error("No command provided.")
        sys.exit(1)

    if getattr(args, "expand", False):
        command = [_expand_vars(arg, env) for arg in command]

    # Run the command directly; do not invoke a shell so the value stays out of
    # the command string visible to the agent.
    try:
        result = subprocess.run(command, env=env, check=False)
    except FileNotFoundError as exc:
        _error(f"command not found: {exc}")
        sys.exit(127)
    sys.exit(result.returncode)


class _GuhioHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Help formatter that preserves description line breaks and aligns options."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=35)


def cmd_version(args) -> None:
    """Print the Guhio version."""
    print(f"guhio {__version__}")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    password_parent = argparse.ArgumentParser(add_help=False)
    password_parent.add_argument(
        "--password",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )

    parser = argparse.ArgumentParser(
        prog="guhio",
        description=(
            "Local password vault for agent workflows.\n\n"
            "Guhio (Sanskrit: गुह्य, \"secret\") keeps credentials encrypted on disk and lets "
            "agents use them by name without exposing plaintext values in prompts or history."
        ),
        formatter_class=_GuhioHelpFormatter,
        epilog=(
            "Examples:\n"
            "  guhio init\n"
            "  guhio add github\n"
            "  guhio unlock\n"
            "  guhio exec --with github:GITHUB_TOKEN -- python script.py\n"
            "  guhio lock\n\n"
            "Run 'guhio <command> --help' for more information on a command."
        ),
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=os.environ.get("GUHIO_VAULT"),
        help="Path to the vault file (default: ~/.guhio/vault.json; can also be set via GUHIO_VAULT env var)",
    )
    parser.add_argument(
        "--password",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"guhio {__version__}",
        help="Show the Guhio version and exit",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a new vault")
    init_parser.set_defaults(func=cmd_init)

    unlock_parser = subparsers.add_parser(
        "unlock",
        parents=[password_parent],
        help="Unlock the vault and create a session for subsequent commands",
    )
    unlock_parser.set_defaults(func=cmd_unlock)

    lock_parser = subparsers.add_parser("lock", help="Lock the vault and clear the session")
    lock_parser.set_defaults(func=cmd_lock)

    add_parser = subparsers.add_parser(
        "add",
        parents=[password_parent],
        help="Add a credential",
    )
    add_parser.add_argument("name", help="Name of the credential")
    add_parser.add_argument(
        "--value",
        default=None,
        help="Value for the credential (prompted securely if omitted)",
    )
    add_parser.set_defaults(func=cmd_add)

    list_parser = subparsers.add_parser(
        "list",
        parents=[password_parent],
        help="List stored credentials",
    )
    list_parser.set_defaults(func=cmd_list)

    remove_parser = subparsers.add_parser(
        "remove",
        parents=[password_parent],
        help="Remove a credential",
    )
    remove_parser.add_argument("name", help="Name of the credential")
    remove_parser.set_defaults(func=cmd_remove)

    get_parser = subparsers.add_parser(
        "get",
        parents=[password_parent],
        help="Print a credential value",
    )
    get_parser.add_argument("name", help="Name of the credential")
    get_parser.set_defaults(func=cmd_get)

    exec_parser = subparsers.add_parser(
        "exec",
        parents=[password_parent],
        help="Run a command with credentials injected as environment variables",
    )
    exec_parser.add_argument(
        "--with",
        dest="with_",
        action="append",
        default=[],
        metavar="NAME:ENV_VAR",
        help="Inject credential NAME as environment variable ENV_VAR",
    )
    exec_parser.add_argument(
        "--expand",
        action="store_true",
        help="Expand $VAR and ${VAR} placeholders in command arguments using the injected environment",
    )
    exec_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command and arguments to run",
    )
    exec_parser.set_defaults(func=cmd_exec)

    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Start the local web dashboard for managing credentials",
    )
    dashboard_parser.add_argument(
        "--host",
        default=os.environ.get("GUHIO_HOST", "127.0.0.1"),
        help="Host to bind the dashboard to (default: 127.0.0.1; can also be set via GUHIO_HOST env var)",
    )
    dashboard_parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("GUHIO_PORT", "5000")),
        help="Port to bind the dashboard to (default: 5000; can also be set via GUHIO_PORT env var)",
    )
    dashboard_parser.add_argument(
        "--debug",
        action="store_true",
        help="Run Flask in debug mode (not recommended with vault sessions)",
    )
    dashboard_parser.set_defaults(func=cmd_dashboard)

    version_parser = subparsers.add_parser(
        "version",
        help="Show the Guhio version and exit",
    )
    version_parser.set_defaults(func=cmd_version)

    return parser


def main() -> None:
    """Entry point for the CLI."""
    # Suppress only the getpass echo warning for piped stdin; allow all other
    # warnings (e.g. cryptography deprecations) to surface.
    warnings.filterwarnings("ignore", message="Password input may be echoed")
    parser = build_parser()
    try:
        args = parser.parse_args()
        args.func(args)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        sys.exit(130)
    except SystemExit:
        raise
    except VaultError as exc:
        _error(exc)
        sys.exit(1)
    except Exception as exc:
        _error(f"an unexpected error occurred: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
