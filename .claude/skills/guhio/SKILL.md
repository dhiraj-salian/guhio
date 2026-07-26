---
name: guhio
description: Use credentials stored in the local Guhio vault without exposing plaintext values. When a task needs a password, token, or secret, prefer guhio exec to inject it as an environment variable. If the credential does not exist, direct the human to add it with guhio add rather than asking for the value in chat.
license: MIT
compatibility: Requires the guhio Python package and a vault initialized with guhio init. Works locally on macOS/Linux/Windows with Python 3.10+.
metadata:
  author: dhiraj-salian
  version: "0.1.0"
---

# Guhio Credential Vault

Guhio is a local encrypted password vault. This skill helps you use stored
credentials safely: the plaintext value stays out of the agent context and
terminal scrollback.

## When to use

- A task requires an API token, password, or other secret.
- The human has previously stored the secret in Guhio.
- You want to run a command or script that needs the secret.

## When NOT to use

- Do not use this skill to request that a human type a password into the chat.
  Instead, ask them to run `guhio add <name>` in their terminal.
- Do not use `guhio get` to print a secret into the agent context unless the
  user explicitly asks for it.

## Core workflow

1. Check whether the needed credential exists:

   ```bash
   guhio list
   ```

   Or run the helper script:

   ```bash
   .claude/skills/guhio/scripts/list-credentials.py
   ```

2. If the credential exists, run the command with it injected as an environment
   variable:

   ```bash
   guhio exec --with github:GITHUB_TOKEN -- curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user
   ```

   The value of `GITHUB_TOKEN` is supplied by Guhio and does not appear in the
   command string you type.

3. If the credential does not exist, tell the human:

   > Please add the credential to Guhio by running:
   >
   > ```bash
   > guhio add <credential-name>
   > ```
   >
   > Then I can use it without you sharing the value here.

## Helper scripts

- `scripts/list-credentials.py` - List available credential names without
  revealing values. Returns JSON.
- `scripts/run-with-credential.py` - Run a command with one or more credentials
  injected as environment variables. Use this when you need to perform an
  operation that requires a secret but you do not want to see the secret.

## Important rules

- Always prefer `guhio exec` (or `scripts/run-with-credential.py`) over
  `guhio get`.
- Never persist a credential value into a file, chat message, or log unless the
  user explicitly requests it.
- If the vault is locked, the human must unlock it by running `guhio unlock` and
  entering the master password.
