# Agent Guide for Guhio

Guhio (Sanskrit: गुह्य, "secret") is a local password vault designed for agent
workflows. It lets humans enter credentials outside the agent's context and lets
agents *use* credentials by name without the plaintext ever appearing in their
prompts or command history.

## Quick Start

```bash
# Create a virtual environment and install in editable mode
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

# Run tests
.venv/bin/python -m pytest

# Run the CLI
.venv/bin/python -m guhio.cli --help
```

Git repository: `git@github.com:dhiraj-salian/guhio.git`

## Essential Commands

| Command | Purpose |
|---------|---------|
| `.venv/bin/python -m pytest` | Run the full test suite. |
| `.venv/bin/python -m guhio.cli init` | Create a new vault. Prompts for a master password securely (no echo). |
| `.venv/bin/python -m guhio.cli add github` | Add a credential. Value is prompted securely unless `--value` is passed. |
| `.venv/bin/python -m guhio.cli list` | List credential names and creation times. Does not show values. |
| `.venv/bin/python -m guhio.cli exec --with github:GITHUB_TOKEN -- curl ...` | Run a command with the credential injected as an environment variable. |
| `.venv/bin/python -m guhio.cli get github` | Reveal a credential value. Prefer `exec` for agent workflows. |
| `.venv/bin/python -m guhio.cli remove github` | Delete a credential. |
| `.venv/bin/python -m guhio.cli dashboard` | Start the local web dashboard on `http://127.0.0.1:5000`. |

The default vault file is `~/.guhio/vault.json`. Use `--vault <path>` or the
`GUHIO_VAULT` environment variable to override.

## Project Structure

```
pyproject.toml          # Build metadata, dependencies, pytest config
src/guhio/
  __init__.py           # Package metadata
  crypto.py             # Encryption primitives (PBKDF2 + Fernet)
  store.py              # Vault class: encrypted JSON file store
  cli.py                # argparse CLI
  dashboard.py          # Flask web dashboard
  templates/
    dashboard.html      # Dashboard UI
.claude/skills/guhio/   # Agent skill following agentskills.io spec
  SKILL.md
  scripts/
    list-credentials.py
    run-with-credential.py
 tests/
  test_crypto.py        # Crypto unit tests
  test_store.py         # Vault persistence and unlock tests
  test_cli.py           # End-to-end subprocess CLI tests
  test_dashboard.py     # Flask test client tests
  test_skill.py         # Agent skill script tests
```

## Architecture and Data Flow

```
Human / script            Vault object (unlocked)            Vault file
    |                            |                               |
    |-- master password -------->|                               |
    |                            |-- PBKDF2 key derivation ---->|
    |                            |<-- salt + verify token --------|
    |                            |                               |
    |-- credential value -------->|                               |
    |                            |-- Fernet encrypt ------------>|
    |                            |                               |
    |<-- "added"                 |-- JSON write ---------------->|
```

Key points:

- The vault file stores a single random **salt**, a **verification token**
  (encrypted known plaintext), and a dictionary of encrypted entries.
- Unlocking derives one Fernet key from the master password + salt, verifies it
  against the verification token, and decrypts every entry into memory.
- Once unlocked, plaintext values live only in the `Vault` object's memory.
- Saving re-encrypts every in-memory value with the vault salt; Fernet's
  internal nonce means ciphertexts change on every save even for unchanged values.

## Agent vs. Human Workflows

**Human provides a password without exposing it to the agent:**

```bash
guhio add github
# Human types the token at the secure terminal prompt.
```

The value is never typed into the chat, terminal scrollback only shows the prompt,
and the stored file is encrypted.

**Agent uses a password without seeing it:**

```bash
guhio exec --with github:GITHUB_TOKEN -- curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user
```

The agent writes the command with the environment variable name, not the value.
`guhio exec` runs the subprocess directly (no shell) with the actual value in
`os.environ`, so the plaintext does not appear in the command string or in process
listings that show argv.

## Agent Skill

A skill conforming to the [Agent Skills specification](https://agentskills.io/specification)
lives in `.claude/skills/guhio/`. It instructs agents to:

- Check credential availability with `guhio list` or `scripts/list-credentials.py`.
- Run commands via `guhio exec` or `scripts/run-with-credential.py`.
- Never ask humans to type secrets into the chat; direct them to `guhio add`.

The skill scripts locate the project root by searching for `pyproject.toml` and
prefer the local `.venv/bin/python -m guhio.cli` when available.

## Dashboard

The dashboard is a Flask app (`src/guhio/dashboard.py`) that binds to
`127.0.0.1:5000` by default.

Important implementation details:

- The dashboard keeps unlocked `Vault` instances in a server-side in-memory
  dictionary keyed by a random session token stored in a signed cookie.
- Because the session store is in memory, Flask's auto-reloader is disabled
  (`use_reloader=False`). Reloading would wipe active sessions and lock users out.
- The dashboard is intended for local, single-user management. Do not expose it
  to a network or run it in a multi-process server.

## Security Model and Gotchas

- This is an MVP. It uses reasonable cryptography (PBKDF2-HMAC-SHA256 at
  600,000 iterations + Fernet/AES-128-CBC + HMAC) but has not undergone a
  security audit.
- The master password is the only protection for the vault file. If an attacker
  obtains both the vault file and the master password, all values are exposed.
- While the vault is unlocked, plaintext values reside in the process memory of
  the `guhio` command or the dashboard process. They are not written to disk
  except in encrypted form.
- `guhio get <name>` intentionally reveals a value. Agents should avoid it.
- The verification token exists so that wrong master passwords are detected even
  when the vault contains no entries. Older vault files without a `verify` field
  will fail to unlock; recreate them if necessary during this early stage.

## CLI Secrets Handling

- `--password <pw>` is a hidden flag (argparse.SUPPRESS). It exists for tests
  and non-interactive scripts, not for routine human use.
- `GUHIO_MASTER_PASSWORD` can also supply the master password. It is primarily
  intended for tests and automation.
- `GUHIO_VAULT` can supply the vault file path when `--vault` is omitted.
- For normal human use, omit all secret flags and let the CLI prompt via `getpass`.

## Code Conventions

- Python 3.10+ with type hints.
- The package is `guhio`, not `password_vault`.
- Exceptions live in `guhio.store` and are subclasses of `VaultError`.
- Tests use `tmp_path` fixtures and subprocess-based CLI tests to exercise the
  real CLI rather than calling internal functions only.
- The CLI parser is built by `build_parser()` and invoked through `main()`.

## Adding New Commands

1. Add a `cmd_<name>` function in `src/guhio/cli.py`.
2. Register it in `build_parser()` via `subparsers.add_parser(...)` and
   `set_defaults(func=cmd_<name>)`.
3. If the command needs the vault unlocked, reuse `_get_password_for_unlock`
   and call `vault.unlock(password)`.
4. Add a subprocess CLI test in `tests/test_cli.py`.

## Adding Dashboard Endpoints

1. Add a route in `src/guhio/dashboard.py`.
2. Use `_require_vault()` for any endpoint that reads or writes credentials.
3. Add a Flask test-client test in `tests/test_dashboard.py` and clear
   `_vault_sessions` in the fixture to avoid state leaking between tests.

## Common Issues

- `KeyError: 'verify'` when unlocking a vault created by an older version of the
  code: the vault format changed. Recreate the vault with `guhio init`.
- Tests that create a vault and then run another CLI subprocess must pass the
  master password via `--password` or `GUHIO_MASTER_PASSWORD`; otherwise the
  second subprocess will block on `getpass`.
- `guhio exec` treats `--` as a separator. If the first token in `args.command`
  is `"--"`, the CLI strips it before passing the rest to `subprocess.run`.
- Dashboard sessions disappear if the server process restarts because they are
  stored in memory. This is by design for local use.
