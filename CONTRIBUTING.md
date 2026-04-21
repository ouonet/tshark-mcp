# Contributing

Thanks for your interest in contributing to tshark-mcp.

## Development Setup

1. Install Python 3.10+.
2. Install dependencies:

```bash
uv pip install -e .
uv add --dev pytest
```

3. Run tests:

```bash
uv run python -m pytest test_server.py -v
```

## Pull Request Guidelines

1. Keep changes focused and small.
2. Add or update tests for behavior changes.
3. Update README when adding or changing tools.
4. Use clear commit messages.
5. Ensure tests pass before opening a PR.

## Reporting Bugs

Please open an issue with:

1. Steps to reproduce.
2. Expected and actual behavior.
3. Environment details (OS, Python version, tshark version).
4. Sample command or tool input (redact sensitive data).
