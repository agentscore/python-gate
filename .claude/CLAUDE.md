# agentscore-gate

Trust-gating middleware for Python web frameworks using AgentScore. Native adapters for FastAPI, Flask, Django, AIOHTTP, and Sanic; generic ASGI middleware covers Starlette/Litestar/Quart.

## Identity Model

All adapters (ASGI, FastAPI, Flask, Django, AIOHTTP, Sanic) support two identity types via `extract_identity`:

- **Wallet address** — `X-Wallet-Address` header
- **Operator token** — `X-Operator-Token` header

Default checks `X-Operator-Token` first, then `X-Wallet-Address`. Types: `AgentIdentity`, `CreateSessionOnMissing` (shared from `agentscore_gate.sessions`), `DenialReason` (codes: `missing_identity`, `identity_verification_required`, `token_expired`, `token_revoked`, `wallet_signer_mismatch`, `wallet_auth_requires_wallet_signing`, `wallet_not_trusted`, `api_error`, `payment_required`), `VerifyWalletSignerMatchOptions`, `VerifyWalletSignerResult`. Client methods: `check_identity()`, `acheck_identity()`, `verify_wallet_signer_match()`, `averify_wallet_signer_match()`.

`create_session_on_missing` is supported on every adapter — when set and no identity found, it creates a verification session and returns 403 with verify_url + poll instructions. Sync-path adapters (Flask/Django) use `try_create_session_denial_reason_sync`; async-path adapters use the async variant. Two optional hooks let merchants inject per-request context: `get_session_options(ctx)` overrides context/product_name per request, and `on_before_session(ctx, session)` runs a side effect after the session mints with its return dict merged into `DenialReason.extra` (surfaces in the 403 body). Both hooks accept sync or `async def` callables (detected via `inspect.iscoroutine`); sync-only adapters skip async hooks with a warning. Hook errors are swallowed with a log.

### Wallet-signer binding

Every adapter exposes `verify_wallet_signer_match(request, signer, network='evm')` (async) or the sync counterpart in Flask/Django. Call AFTER the agent submits a payment credential, BEFORE settlement. Extract the signer from the payment payload (EIP-3009 `from`, Tempo MPP DID, etc.). Returns a `VerifyWalletSignerResult` with `kind: "pass" | "wallet_signer_mismatch" | "wallet_auth_requires_wallet_signing"`. Non-pass variants carry `claimed_operator`, `actual_signer_operator`, `expected_signer`, `actual_signer`, `linked_wallets` (same-operator sibling wallets that would also be accepted). No-ops for operator-token requests or when both identity headers were sent. Shared response marshalling lives in `agentscore_gate/_response.py` (`denial_reason_to_body`).

### Cross-merchant agent memory

`DenialReason.agent_memory` carries a cross-merchant bootstrap hint (built via `build_agent_memory_hint(base_url)`). Emitted on `missing_identity` denials with no auto-session. The `_response.py` marshaller serializes it via `asdict` as the `agent_memory` field in the 403 body.

### Captured wallets (TEC-189)

Every adapter exposes a `capture_wallet` helper that merchants call after a successful payment to report the signer wallet back to AgentScore. The gate middleware stashes the extracted `operator_token` on the request/context during gating; `capture_wallet` reads it and calls `POST /v1/credentials/wallets` fire-and-forget. No-ops silently when the request was wallet-authenticated (no operator_token), the gate didn't run, or the API call fails.

`idempotency_key` (payment intent id, tx hash, …) lets the server dedupe agent retries of the same payment so `transaction_count` isn't inflated.

- ASGI: `from agentscore_gate.middleware import capture_wallet` → `await capture_wallet(request, wallet_address, network, idempotency_key=None)`
- FastAPI (native): `from agentscore_gate.fastapi import capture_wallet` → `await capture_wallet(request, wallet_address, network, idempotency_key=None)`
- Flask: `from agentscore_gate.flask import capture_wallet` → `capture_wallet(wallet_address, network, idempotency_key=None)` (reads Flask `g`)
- Django: `from agentscore_gate.django import capture_wallet` → `capture_wallet(request, wallet_address, network, idempotency_key=None)`
- AIOHTTP: `from agentscore_gate.aiohttp import capture_wallet` → `await capture_wallet(request, wallet_address, network, idempotency_key=None)`
- Sanic: `from agentscore_gate.sanic import capture_wallet` → `await capture_wallet(request, wallet_address, network, idempotency_key=None)`

Underlying HTTP lives on `GateClient.capture_wallet(...)` / `GateClient.acapture_wallet(...)` — same signature as node-gate's `core.captureWallet()`.

## Architecture

Single-package Python library published to PyPI.

| File | Purpose |
|------|---------|
| `agentscore_gate/` | Source code |
| `agentscore_gate/middleware.py` | Generic ASGI middleware (Starlette/Litestar/Quart) |
| `agentscore_gate/fastapi.py` | FastAPI native adapter: `AgentScoreGate` (callable Depends) + `get_assess_data` |
| `agentscore_gate/flask.py` | Flask adapter |
| `agentscore_gate/django.py` | Django adapter |
| `agentscore_gate/aiohttp.py` | AIOHTTP adapter (native middleware, not ASGI-compatible) |
| `agentscore_gate/sanic.py` | Sanic adapter |
| `agentscore_gate/sessions.py` | Shared `CreateSessionOnMissing` + sync/async session-creation helpers |
| `agentscore_gate/client.py` | Shared `GateClient` (assess + capture + cache) |
| `tests/` | pytest tests (one file per adapter) |

## Tooling

- **uv** — package manager. Use `uv sync`, `uv run`.
- **ruff** — linting + formatting. `uv run ruff check .` and `uv run ruff format --check .`.
- **ty** — type checker (Astral). `uv run ty check agentscore_gate/`.
- **vulture** — dead code detection.
- **pytest** — tests. `uv run pytest tests/`.
- **Lefthook** — git hooks. Pre-commit: ruff. Pre-push: ty + vulture (parallel).

## Key Commands

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format .
uv run ty check agentscore_gate/
uv run pytest tests/
```

## Workflow

1. Create a branch
2. Make changes
3. Lefthook runs ruff on commit, ty + vulture on push
4. Open a PR — CI runs automatically
5. Merge (squash)

## Rules

- **No silent refactors**
- **Never commit .env files or secrets**
- **Use PRs** — never push directly to main

## Releasing

1. Update `version` in `pyproject.toml`
2. Commit: `git commit -am "chore: bump to vX.Y.Z"`
3. Tag: `git tag vX.Y.Z`
4. Push: `git push && git push origin vX.Y.Z`

The publish workflow runs on `ubuntu-latest` (required for PyPI trusted publishing), builds, publishes to PyPI via OIDC, and creates a GitHub Release.
