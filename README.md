# agentscore-gate

[![PyPI version](https://img.shields.io/pypi/v/agentscore-gate.svg)](https://pypi.org/project/agentscore-gate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Identity-gating middleware for Python web frameworks using [AgentScore](https://agentscore.sh). Native adapters for FastAPI, Flask, Django, AIOHTTP, and Sanic; generic ASGI middleware for Starlette / Litestar / Quart.

## Install

```bash
pip install agentscore-gate
```

## Quick Start

### FastAPI (native `Depends()`)

```python
from fastapi import Depends, FastAPI
from agentscore_gate.fastapi import AgentScoreGate, get_assess_data

app = FastAPI()
gate = AgentScoreGate(api_key="as_live_...", require_kyc=True, min_age=21)

@app.post("/purchase", dependencies=[Depends(gate)])
async def purchase(assess = Depends(get_assess_data)):
    # `assess` is the raw /v1/assess response (or None if fail_open)
    ...
```

### Starlette / other ASGI (FastAPI users can use this too)

```python
from starlette.applications import Starlette
from agentscore_gate import AgentScoreGate

app = Starlette()
app.add_middleware(AgentScoreGate, api_key="as_live_...", require_kyc=True)
```

### Flask

```python
from flask import Flask
from agentscore_gate.flask import agentscore_gate

app = Flask(__name__)
agentscore_gate(app, api_key="as_live_...", require_kyc=True)
```

### Django

```python
# settings.py
MIDDLEWARE = ["agentscore_gate.django.AgentScoreMiddleware"]
AGENTSCORE_GATE = {
    "api_key": "as_live_...",
    "require_kyc": True,
}
```

### AIOHTTP

```python
from aiohttp import web
from agentscore_gate.aiohttp import agentscore_gate_middleware

app = web.Application()
app.middlewares.append(agentscore_gate_middleware(api_key="as_live_...", require_kyc=True))
```

### Sanic

```python
from sanic import Sanic
from agentscore_gate.sanic import agentscore_gate

app = Sanic("myapp")
agentscore_gate(app, api_key="as_live_...", require_kyc=True)
```

## Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `api_key` | `str` | *required* | API key |
| `require_kyc` | `bool` | `None` | Require KYC verification |
| `require_sanctions_clear` | `bool` | `None` | Require clean sanctions status |
| `min_age` | `int` | `None` | Minimum age bracket (18 or 21) |
| `blocked_jurisdictions` | `list[str]` | `None` | ISO country codes to block |
| `allowed_jurisdictions` | `list[str]` | `None` | ISO country codes to allow |
| `fail_open` | `bool` | `False` | Allow requests when API unreachable |
| `cache_seconds` | `int` | `300` | Cache TTL |
| `user_agent` | `str` | `None` | Prepended to the default `User-Agent` as `"{user_agent} (agentscore-gate/{version})"`. Use to attribute API calls to your app. |
| `extract_identity` | `callable` | Reads headers | Custom identity extractor |
| `create_session_on_missing` | `CreateSessionOnMissing` | `None` | Auto-create verification session when no identity is found (all adapters) |

## Identity

Checks `X-Operator-Token` first, then `X-Wallet-Address`:

```python
from agentscore_gate import AgentIdentity

app.add_middleware(
    AgentScoreGate,
    api_key="as_live_...",
    extract_identity=lambda req: AgentIdentity(
        operator_token=req.headers.get("x-operator-token"),
        address=req.headers.get("x-wallet-address"),
    ),
)
```

### Denial bodies

Every 403 body carries `agent_instructions` — a JSON-encoded `{action, steps, user_message}` block so agents act from the response itself, no discovery-doc round trip. Actions:

| Code | `action` |
|---|---|
| `missing_identity` | `probe_identity_then_session` (try wallet on signing rails → stored opc_... → session flow) |
| `wallet_signer_mismatch` | `resign_or_switch_to_operator_token` (body also carries `claimed_operator`, `actual_signer_operator`, `expected_signer`, `actual_signer`, `linked_wallets`) |
| `wallet_auth_requires_wallet_signing` | `switch_to_operator_token` |
| `token_expired` | `mint_new_credential` |

### Auto-Create Session

Works on every adapter (ASGI, FastAPI, Flask, Django, AIOHTTP, Sanic).

```python
from agentscore_gate.sessions import CreateSessionOnMissing

app.add_middleware(
    AgentScoreGate,
    api_key="as_live_...",
    create_session_on_missing=CreateSessionOnMissing(api_key="as_live_..."),
)
# 403 includes: verify_url, session_id, poll_secret, poll_url, agent_instructions, agent_memory
```

### Per-request hooks

For per-product session context or pre-session side effects (e.g. pre-creating a pending order):

```python
async def wine_name(request):
    body = await request.json()
    product = await lookup_product(body["product_id"])
    return {"product_name": product.name}

async def create_pending(request, session):
    body = await request.json()
    order_id = await db.insert_pending_order(body["product_id"], session["session_id"])
    return {"order_id": order_id}  # merged into DenialReason.extra → surfaces in the 403 body

create_session_on_missing=CreateSessionOnMissing(
    api_key="as_live_...",
    get_session_options=wine_name,
    on_before_session=create_pending,
)
```

Hooks can be sync or `async def`. Flask and Django (sync adapters) accept only sync hooks — async hooks are skipped with a warning.

## Capture the wallet after payment

After a successful payment, report the signer wallet back to AgentScore so it can build a cross-merchant credential↔wallet profile. Each adapter exposes a `capture_wallet` helper that reads the operator_token the gate already extracted.

### FastAPI (native `Depends()`)

```python
from fastapi import Depends, Request
from agentscore_gate.fastapi import AgentScoreGate, capture_wallet, get_assess_data

@app.post("/purchase", dependencies=[Depends(gate)])
async def purchase(request: Request, assess = Depends(get_assess_data)):
    # ... run payment, recover signer wallet from the payload ...
    await capture_wallet(request, signer, "evm", idempotency_key=payment_intent_id)
    return {"ok": True}
```

### Starlette / other ASGI

```python
from agentscore_gate.middleware import capture_wallet

@app.post("/purchase")
async def purchase(request: Request):
    await capture_wallet(request, signer, "evm", idempotency_key=payment_intent_id)
    return {"ok": True}
```

### Flask

```python
from agentscore_gate.flask import capture_wallet

@app.post("/purchase")
def purchase():
    capture_wallet(signer, "evm", idempotency_key=payment_intent_id)
    return {"ok": True}
```

### Django

```python
from agentscore_gate.django import capture_wallet

def purchase(request):
    capture_wallet(request, signer, "evm", idempotency_key=payment_intent_id)
    return JsonResponse({"ok": True})
```

### AIOHTTP

```python
from agentscore_gate.aiohttp import capture_wallet

async def purchase(request):
    await capture_wallet(request, signer, "evm", idempotency_key=payment_intent_id)
    return web.json_response({"ok": True})
```

### Sanic

```python
from agentscore_gate.sanic import capture_wallet

@app.post("/purchase")
async def purchase(request):
    await capture_wallet(request, signer, "evm", idempotency_key=payment_intent_id)
    return response.json({"ok": True})
```

Fire-and-forget by design: silently no-ops if the request was wallet-authenticated (no operator_token), the gate didn't run, or the API call fails. `idempotency_key` (payment intent id, tx hash, …) prevents agent retries of the same payment from inflating `transaction_count` server-side.

## Verify wallet signer match

Verify the payment signer resolves to the same AgentScore operator as the claimed `X-Wallet-Address`. Call after the agent submits a payment credential, before settlement. Each adapter exposes `verify_wallet_signer_match` — async on FastAPI/AIOHTTP/Sanic/ASGI, sync on Flask/Django. No-ops on operator-token requests.

```python
# FastAPI (async)
from agentscore_gate.fastapi import verify_wallet_signer_match

@app.post("/purchase", dependencies=[Depends(gate)])
async def purchase(request: Request):
    match = await verify_wallet_signer_match(request, signer=recovered_signer)
    if match.kind != "pass":
        return JSONResponse({"error": match.kind, **match.__dict__}, status_code=403)
    # ... settle payment ...
```

`match.kind` is `"pass" | "wallet_signer_mismatch" | "wallet_auth_requires_wallet_signing" | "api_error"`. Non-pass / non-api_error variants include `claimed_operator`, `actual_signer_operator`, `expected_signer`, `actual_signer`, `linked_wallets`, and `agent_instructions` (JSON-encoded action copy merchants spread directly into the 403 body).

Available on every adapter (`fastapi`, `flask`, `django`, `aiohttp`, `sanic`, `middleware`). Flask and Django use sync signatures; others use async.

## Documentation

- [API Reference](https://docs.agentscore.sh)

## License

[MIT](LICENSE)
