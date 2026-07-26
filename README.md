# Guhio

[![PyPI version](https://img.shields.io/pypi/v/guhio.svg)](https://pypi.org/project/guhio/)

Guhio (Sanskrit: गुह्य, "secret") is a local password vault for agent workflows.
Humans store credentials outside the agent context, and agents use them by name
without ever seeing the plaintext values.

## Features

- Encrypted local vault using PBKDF2-HMAC-SHA256 (600,000 iterations) and
  Fernet symmetric encryption (AES-128-CBC + HMAC).
- Atomic, permission-restricted vault writes.
- CLI with secure `getpass` prompts and a non-interactive `exec` mode that
  injects credentials as environment variables.
- Encrypted CLI sessions so you unlock once and run multiple commands.
- Local web dashboard for managing credentials in a browser.
- Agent skill under `.claude/skills/guhio/` following the
  [Agent Skills specification](https://agentskills.io/specification).

## Installation

```bash
pip install guhio
```

## Quick start

```bash
# Create a vault
 guhio init

# Add a credential (value is prompted securely)
 guhio add github

# Unlock once and reuse the session
 eval $(guhio unlock)

# Use the credential without exposing the value
 guhio exec --with github:GITHUB_TOKEN --expand -- \
   curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Lock the vault and clear the session
 guhio lock
```

## Commands

| Command | Purpose |
|---------|---------|
| `guhio init` | Create a new vault. |
| `guhio add <name>` | Add a credential. Use `--value <value>` to skip prompting. |
| `guhio list` | List credential names and creation times. |
| `guhio get <name>` | Print a credential value. |
| `guhio unlock` | Unlock the vault and print `export GUHIO_SESSION=...`. |
| `guhio lock` | Clear the CLI session. |
| `guhio exec --with <name>:<ENV_VAR> [--expand] -- <command>` | Run a command with the credential injected as an environment variable. |
| `guhio remove <name>` | Delete a credential. |
| `guhio dashboard` | Start the local web dashboard (default `http://127.0.0.1:5000`). |

## Authentication

The master password can be supplied in three ways, in order of precedence:

1. `GUHIO_SESSION` environment variable from `guhio unlock`.
2. `GUHIO_MASTER_PASSWORD` environment variable.
3. The hidden `--password <pw>` flag.
4. Interactive `getpass` prompt.

Run `guhio lock` to remove the session file at `~/.guhio/session.json`.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `GUHIO_VAULT` | Path to the vault file (default: `~/.guhio/vault.json`). |
| `GUHIO_MASTER_PASSWORD` | Master password for non-interactive use. |
| `GUHIO_SESSION` | Session token from `guhio unlock`. |
| `GUHIO_HOST` / `GUHIO_PORT` | Dashboard bind address and port. |

## Dashboard

```bash
guhio dashboard              # http://127.0.0.1:5000
guhio dashboard --port 8080
```

The dashboard stores unlocked vaults in server-side memory; sessions disappear
when the server restarts. Do not expose the dashboard to untrusted networks.

## Security notes

- The master password is the only protection for the vault file.
- Vault files are written atomically with mode `0600`.
- `guhio exec` runs commands directly (not through a shell). Use `--expand` to
  substitute `$VAR` placeholders, or `sh -c '...'` for full shell features.
- Never commit vault files to version control.

This is an MVP with reasonable cryptography; it has not undergone a formal
security audit.

## Development and contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup, testing, and contribution
guidelines.

## License

MIT
