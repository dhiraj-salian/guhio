# Guhio

Guhio (Sanskrit: गुह्य, "secret") is a local password vault built for agent
workflows. It lets humans provide credentials without typing them into an agent
context, and it lets agents *use* credentials by name without ever seeing the
plaintext values.

## Features

- **Encrypted local vault** using PBKDF2 key derivation and Fernet symmetric
  encryption.
- **Human-friendly CLI** with secure password prompts.
- **Agent-safe usage** via `guhio exec`, which injects credentials into a
  subprocess as environment variables.
- **Agent skill** following the [Agent Skills](https://agentskills.io/specification)
  format so AI assistants can discover and use the vault safely.
- **Local web dashboard** for adding, viewing, and managing credentials in a
  browser.

## Installation

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## CLI Usage

```bash
# Create a vault
.venv/bin/python -m guhio.cli init

# Add a credential (prompts securely)
.venv/bin/python -m guhio.cli add github

# List credentials
.venv/bin/python -m guhio.cli list

# Use a credential without revealing it
.venv/bin/python -m guhio.cli exec --with github:GITHUB_TOKEN -- curl \
  -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Remove a credential
.venv/bin/python -m guhio.cli remove github
```

The default vault file is `~/.guhio/vault.json`. Use `--vault <path>` to
override.

## Dashboard

Start the local web dashboard:

```bash
.venv/bin/python -m guhio.cli dashboard
```

Then open <http://127.0.0.1:5000> in your browser. The dashboard only binds to
localhost and requires the master password to unlock the vault.

## Agent Skill

A skill conforming to the [Agent Skills specification](https://agentskills.io/specification)
is included under `.claude/skills/guhio/`. When loaded, it instructs agents to
use `guhio exec` for credential-based operations and to direct humans to
`guhio add` when a credential is missing.

## Development

```bash
.venv/bin/python -m pytest
```

## Security Notes

This is an MVP. The vault is only as strong as the master password and the
security of the machine it runs on. While unlocked, plaintext values reside in
process memory. Do not commit vault files to version control.
