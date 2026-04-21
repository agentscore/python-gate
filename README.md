# agentscore-gate

[![PyPI version](https://img.shields.io/pypi/v/agentscore-gate.svg)](https://pypi.org/project/agentscore-gate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Identity-gating middleware for Python web frameworks using [AgentScore](https://agentscore.sh). Works with FastAPI, Starlette, Flask, and Django.

## Install

```bash
pip install agentscore-gate
```

## Quick Start

### FastAPI

```python
from fastapi import FastAPI
from agentscore_gate import AgentScoreGate

app = FastAPI()
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
| `create_session_on_missing` | `CreateSessionOnMissing` | `None` | Auto-create session (ASGI only) |

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

### Auto-Create Session (ASGI)

```python
from agentscore_gate.middleware import CreateSessionOnMissing

app.add_middleware(
    AgentScoreGate,
    api_key="as_live_...",
    create_session_on_missing=CreateSessionOnMissing(api_key="as_live_..."),
)
# 403 includes: verify_url, session_id, poll_secret, agent_instructions
```

## Documentation

- [API Reference](https://docs.agentscore.sh)

## License

[MIT](LICENSE)
