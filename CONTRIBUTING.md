# Contributing to Guhio

Thank you for your interest in improving Guhio! This guide covers how to set up
a development environment, run tests, and contribute changes.

## Development setup

1. Fork and clone the repository:

   ```bash
   git clone https://github.com/dhiraj-salian/guhio.git
   cd guhio
   ```

2. Create a virtual environment and install the package in editable mode with
   development dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```

## Running tests

The test suite uses `pytest` and exercises the real CLI via subprocess:

```bash
python -m pytest
```

Run with `-v` for verbose output:

```bash
python -m pytest -v
```

All tests should pass before opening a pull request.

## Project structure

```
pyproject.toml          # Build metadata and dependencies
src/guhio/
  __init__.py           # Package metadata
  crypto.py             # Encryption primitives
  session.py            # Encrypted CLI session persistence
  store.py              # Vault class
  cli.py                # argparse CLI
  dashboard.py          # Flask web dashboard
  templates/
    dashboard.html
tests/                  # pytest test suite
.claude/skills/guhio/   # Agent skill and helper scripts
```

## Code conventions

- Python 3.10+ with type hints.
- Follow the existing style and naming.
- Keep the CLI secure: avoid logging or echoing secret values.
- Add subprocess-based CLI tests for new commands or behavior.
- Update `README.md` and this guide if you change user-facing behavior.

## Submitting changes

1. Create a feature branch:

   ```bash
   git checkout -b your-name/feature-description
   ```

2. Make your changes and ensure tests pass.

3. Commit with a clear message explaining *why* the change matters.

4. Push to your fork and open a pull request against `main`.

5. Pull requests are merged after review and a passing CI run.

## Reporting issues

Open a [GitHub issue](https://github.com/dhiraj-salian/guhio/issues) and include:

- Guhio version (`guhio --version` or `pip show guhio`).
- Python version and operating system.
- Steps to reproduce the problem.
- Expected and actual behavior.

## Security issues

Please do not open public issues for security vulnerabilities. Email the
maintainer directly or follow the project's security policy if one is published.

## Release process

Releases are automated via GitHub Actions. To publish a new version:

1. Update the version in `pyproject.toml`.
2. Ensure the changelog or release notes are up to date.
3. Create and push a version tag:

   ```bash
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```

4. GitHub Actions builds the package and publishes it to PyPI using the
   `PYPI_API_TOKEN` repository secret.

Maintainers should also create a GitHub Release from the tag with a summary of
changes.
