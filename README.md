# Guhio

[![PyPI version](https://img.shields.io/pypi/v/guhio.svg)](https://pypi.org/project/guhio/)

Guhio (Sanskrit: गुह्य, "secret") is a local password vault built for agent
workflows. It lets humans provide credentials without typing them into an agent
context, and it lets agents *use* credentials by name without ever seeing the
plaintext values.

## Features

- **Encrypted local vault** using PBKDF2-HMAC-SHA256 key derivation (600,000
  iterations) and Fernet symmetric encryption (AES-128-CBC + HMAC).
- **Atomic, permission-restricted storage** — the vault is written to a
  temporary file and renamed into place, so a crash never leaves a truncated
  vault, and the file is created with mode `0600` (owner read/write only).
- **Human-friendly CLI** with secure `getpass` prompts (no echo).
- **Agent-safe usage** via `guhio exec`, which injects credentials into a
  subprocess as environment variables — the plaintext never appears in the
  command string or in process `argv`.
- **Local web dashboard** for adding, viewing, and managing credentials in a
  browser, with XSS-safe rendering of credential names.
- **Agent skill** following the [Agent Skills](https://agentskills.io/specification)
  format so AI assistants can discover and use the vault safely.

## Installation

Install the published package from PyPI:

```bash
pip install guhio
```

For development, install in editable mode with the test dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## CLI Usage

The `guhio` command is installed as a console entry point. From a development
checkout you can also run `python -m guhio.cli`.

```bash
# Create a vault (prompts twice for a new master password)
guhio init

# Add a credential (value is prompted securely unless --value is given)
guhio add github

# List credentials (names and creation times; never shows values)
guhio list

# Reveal a credential value (for humans/scripts; agents should prefer exec)
guhio get github

# Use a credential without revealing it — the value is injected as an env var
guhio exec --with github:GITHUB_TOKEN -- curl \
  -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Remove a credential
guhio remove github
```

The default vault file is `~/.guhio/vault.json`. Override it with `--vault <path>`
or the `GUHIO_VAULT` environment variable.

For automation and tests, the master password can be supplied via the
`GUHIO_MASTER_PASSWORD` environment variable or the hidden `--password` flag.
For normal interactive use, omit both and enter the password at the secure
prompt.

## Dashboard

Start the local web dashboard:

```bash
# Default: http://127.0.0.1:5000
guhio dashboard

# Run on a different port
guhio dashboard --port 8080

# Or configure host and port via environment variables
GUHIO_PORT=8080 guhio dashboard
GUHIO_HOST=0.0.0.0 GUHIO_PORT=8080 guhio dashboard   # bind to all interfaces
```

The dashboard binds to `127.0.0.1:5000` by default. Override the host and port
with the `--host` / `--port` flags or the `GUHIO_HOST` / `GUHIO_PORT`
environment variables. The flag always wins over the environment variable. It
requires the master password to unlock the vault.

> Binding to `0.0.0.0` exposes the dashboard to your network. The dashboard is
> intended for local, single-user management — do not expose it to untrusted
> networks.

The dashboard keeps unlocked vaults in an in-memory, server-side session store
(keyed by a random token in a signed cookie), so Flask's auto-reloader is
disabled. Sessions disappear when the server process restarts; this is by
design for local use.

## Agent Skill

A skill conforming to the [Agent Skills specification](https://agentskills.io/specification)
is included under `.claude/skills/guhio/`. When loaded, it instructs agents to
use `guhio exec` for credential-based operations and to direct humans to
`guhio add` when a credential is missing, so secret values never enter the chat.

## Development

```bash
.venv/bin/python -m pytest
```

## Security Notes

This is an MVP. It uses reasonable cryptography (PBKDF2-HMAC-SHA256 at 600,000
iterations + Fernet/AES-128-CBC + HMAC) but has not undergone a formal security
audit.

- The master password is the only protection for the vault file. If an attacker
  obtains both the vault file and the master password, all values are exposed.
- The vault file is written atomically (temp file + `os.replace`) with mode
  `0600`, so a crash mid-save cannot corrupt or truncate the store and other
  users on the system cannot read the encrypted contents.
- While the vault is unlocked, plaintext values reside only in the process
  memory of the `guhio` command or the dashboard process. They are never
  written to disk except in encrypted form.
- The dashboard renders credential names with DOM APIs (`textContent` and
  `addEventListener`) rather than `innerHTML`, preventing stored XSS through
  crafted credential names.
- Do not commit vault files to version control.
