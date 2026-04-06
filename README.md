# agentscore-gate

[![PyPI version](https://img.shields.io/pypi/v/agentscore-gate.svg)](https://pypi.org/project/agentscore-gate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

ASGI middleware for trust-gating requests using [AgentScore](https://agentscore.sh). Verify AI agent wallet reputation before allowing requests through. Works with FastAPI, Starlette, and any ASGI framework.

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
app.add_middleware(AgentScoreGate, api_key="as_live_...", min_score=50)

@app.get("/")
async def root():
    return {"message": "Hello, trusted agent!"}
```

### Starlette

```python
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from agentscore_gate import AgentScoreGate

async def homepage(request):
    agentscore_data = request.state.agentscore
    return PlainTextResponse("Hello, trusted agent!")

app = Starlette(routes=[Route("/", homepage)])
app.add_middleware(AgentScoreGate, api_key="as_live_...", min_score=50)
```

## Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str` | *required* | API key from [agentscore.sh](https://agentscore.sh) |
| `min_score` | `int \| None` | `None` | Minimum score (0–100) |
| `min_grade` | `str \| None` | `None` | Minimum grade (A–F) |
| `require_verified_activity` | `bool \| None` | `None` | Require verified payment activity |
| `require_kyc` | `bool \| None` | `None` | Require KYC verification |
| `require_sanctions_clear` | `bool \| None` | `None` | Require clean sanctions status |
| `min_age` | `int \| None` | `None` | Minimum age (18 or 21) |
| `blocked_jurisdictions` | `list[str] \| None` | `None` | ISO country codes to block |
| `require_entity_type` | `str \| None` | `None` | Required operator type (`individual` or `entity`) |
| `chain` | `str \| None` | `None` | Optional chain filter for scoring |
| `fail_open` | `bool` | `False` | Allow requests when API is unreachable |
| `cache_seconds` | `int` | `300` | Cache TTL for results |
| `base_url` | `str` | `https://api.agentscore.sh` | API base URL |
| `extract_address` | `callable` | Reads `x-wallet-address` header | Custom address extractor |
| `on_denied` | `async callable` | Returns 403 JSON | Custom denial handler |

## How It Works

1. Extracts wallet address from request header (`x-wallet-address`)
2. Checks in-memory cache for a previous result
3. Calls AgentScore `/v1/assess` with your policy
4. Allows or blocks based on the decision
5. Attaches data to `request.state.agentscore` on allowed requests

## Compliance Gating

```python
app.add_middleware(
    AgentScoreGate,
    api_key="as_live_...",
    min_grade="B",
    require_kyc=True,
    require_sanctions_clear=True,
    min_age=18,
    blocked_jurisdictions=["KP", "IR", "CU"],
    require_entity_type="individual",
)
```

## Documentation

- [API Reference](https://docs.agentscore.sh)

## License

[MIT](LICENSE)
