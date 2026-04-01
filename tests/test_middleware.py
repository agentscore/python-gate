import json

import httpx
import pytest
import respx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from agentscore_gate import AgentScoreGate
from agentscore_gate.types import DenialReason

API_KEY = "ask_test_key"
BASE_URL = "https://api.agentscore.sh"
ASSESS_URL = f"{BASE_URL}/v1/assess"


def _make_app(
    *,
    min_score=None,
    min_grade=None,
    fail_open=False,
    extract_address=None,
    on_denied=None,
    cache_seconds=300,
):
    async def homepage(request: Request):
        agentscore_data = request.state.agentscore if hasattr(request.state, "agentscore") else None
        return PlainTextResponse(f"ok:{agentscore_data}")

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(
        AgentScoreGate,
        api_key=API_KEY,
        min_score=min_score,
        min_grade=min_grade,
        fail_open=fail_open,
        extract_address=extract_address,
        on_denied=on_denied,
        cache_seconds=cache_seconds,
    )
    return app


@pytest.fixture
def app():
    return _make_app(min_score=50)


@pytest.fixture
def client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


@pytest.mark.anyio
@respx.mock
async def test_allow_request(client):
    respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"decision": "allow", "decision_reasons": [], "score": 85},
        )
    )

    resp = await client.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 200
    assert resp.text.startswith("ok:")


@pytest.mark.anyio
@respx.mock
async def test_deny_request(client):
    respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"decision": "deny", "decision_reasons": ["score_below_threshold"]},
        )
    )

    resp = await client.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"] == "wallet_not_trusted"
    assert "score_below_threshold" in body["reasons"]


@pytest.mark.anyio
async def test_missing_wallet_address(client):
    resp = await client.get("/")
    assert resp.status_code == 403
    assert resp.json()["error"] == "missing_wallet_address"


@pytest.mark.anyio
async def test_missing_wallet_fail_open():
    app = _make_app(min_score=50, fail_open=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/")
    assert resp.status_code == 200


@pytest.mark.anyio
@respx.mock
async def test_api_error_fail_closed(client):
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(500))

    resp = await client.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 403
    assert resp.json()["error"] == "api_error"


@pytest.mark.anyio
@respx.mock
async def test_api_error_fail_open():
    app = _make_app(min_score=50, fail_open=True)
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(500))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 200


@pytest.mark.anyio
@respx.mock
async def test_payment_required_fail_open():
    app = _make_app(min_score=50, fail_open=True)
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(402))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 200


@pytest.mark.anyio
@respx.mock
async def test_payment_required_fail_closed(client):
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(402))

    resp = await client.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 403
    assert resp.json()["error"] == "payment_required"


@pytest.mark.anyio
@respx.mock
async def test_caches_result(client):
    route = respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"decision": "allow", "decision_reasons": [], "score": 90},
        )
    )

    await client.get("/", headers={"x-wallet-address": "0xABC123"})
    await client.get("/", headers={"x-wallet-address": "0xABC123"})

    assert route.call_count == 1


@pytest.mark.anyio
@respx.mock
async def test_null_decision_allows():
    """When the API returns decision=null, the request should be allowed."""
    app = _make_app(min_score=50)
    respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"decision": None, "decision_reasons": [], "score": 75},
        )
    )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 200


@pytest.mark.anyio
@respx.mock
async def test_custom_on_denied():
    async def custom_denied(request: Request, reason: DenialReason) -> JSONResponse:
        return JSONResponse({"blocked": True, "code": reason.code}, status_code=429)

    app = _make_app(min_score=50, on_denied=custom_denied)
    respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(200, json={"decision": "deny", "decision_reasons": ["low_score"]})
    )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 429
    assert resp.json()["blocked"] is True


@pytest.mark.anyio
@respx.mock
async def test_policy_sent_in_request():
    """Verify that min_score and min_grade are sent in the policy body."""
    app = _make_app(min_score=60, min_grade="B")

    def check_body(request):
        body = json.loads(request.content)
        assert body["policy"]["min_score"] == 60
        assert body["policy"]["min_grade"] == "B"
        return httpx.Response(200, json={"decision": "allow", "decision_reasons": []})

    respx.post(ASSESS_URL).mock(side_effect=check_body)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 200


def test_missing_api_key_raises():
    async def homepage(request):
        return PlainTextResponse("ok")

    with pytest.raises(ValueError, match="API key is required"):
        AgentScoreGate(Starlette(routes=[Route("/", homepage)]), api_key="")


@pytest.mark.anyio
async def test_websocket_scope_passes_through():
    received = []

    async def inner_app(scope, receive, send):
        received.append(scope["type"])

    app = AgentScoreGate(inner_app, api_key=API_KEY, min_score=50)
    scope = {"type": "websocket", "headers": []}

    async def noop_receive():
        return {}

    async def noop_send(msg):
        pass

    await app(scope, noop_receive, noop_send)
    assert received == ["websocket"]


@pytest.mark.anyio
@respx.mock
async def test_custom_extract_address():
    def extract_from_query(request: Request) -> str | None:
        return request.query_params.get("wallet")

    app = _make_app(min_score=50, extract_address=extract_from_query)
    respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(
            200,
            json={"decision": "allow", "decision_reasons": []},
        )
    )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/?wallet=0xABC123")
    assert resp.status_code == 200
    assert resp.text.startswith("ok:")


@pytest.mark.anyio
@respx.mock
async def test_address_lowercased_for_cache():
    """Cache key should normalize address to lowercase."""
    app = _make_app(min_score=50)
    route = respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(200, json={"decision": "allow", "decision_reasons": []})
    )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        await c.get("/", headers={"x-wallet-address": "0xABC123"})
        await c.get("/", headers={"x-wallet-address": "0xabc123"})

    assert route.call_count == 1
