# agentscore-gate

Trust-gating middleware for Python web frameworks using AgentScore. Includes adapters for Flask, Django, and Starlette/FastAPI.

## Architecture

Single-package Python library published to PyPI.

| File | Purpose |
|------|---------|
| `agentscore_gate/` | Source code |
| `agentscore_gate/flask.py` | Flask adapter |
| `agentscore_gate/django.py` | Django adapter |
| `agentscore_gate/middleware.py` | ASGI/Starlette middleware |
| `tests/` | pytest tests |

## Tooling

- **uv** — package manager. Use `uv sync`, `uv run`.
- **ruff** — linting + formatting. `uv run ruff check .` and `uv run ruff format --check .`.
- **vulture** — dead code detection.
- **pytest** — tests. `uv run pytest tests/`.
- **Lefthook** — git hooks. Pre-commit: ruff. Pre-push: vulture.

## Key Commands

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format .
uv run pytest tests/
```

## Workflow

1. Create a branch
2. Make changes
3. Lefthook runs ruff on commit, vulture on push
4. Open a PR — CI runs automatically
5. Merge (squash)

## Rules

- **No silent refactors**
- **Never commit .env files or secrets**
- **Use PRs** — never push directly to main
