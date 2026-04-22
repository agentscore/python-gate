"""Tests for the ASGI middleware (Starlette/FastAPI)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import respx
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agentscore_gate.middleware import AgentScoreGate, CreateSessionOnMissing

if TYPE_CHECKING:
    from starlette.requests import Request

ASSESS_URL = "https://api.agentscore.sh/v1/assess"
SESSIONS_URL = "https://api.agentscore.sh/v1/sessions"

SESSION_RESPONSE = {
    "session_id": "sess_abc123",
    "verify_url": "https://agentscore.sh/verify/sess_abc123",
    "poll_secret": "ps_secret_456",
    "agent_instructions": "Please complete identity verification at the verify_url.",
}


def _homepage(request: Request) -> JSONResponse:
    agentscore_data = request.state.agentscore if hasattr(request.state, "agentscore") else None
    return JSONResponse({"ok": True, "agentscore": agentscore_data})


def _make_app(**gate_kwargs: object) -> Starlette:
    app = Starlette(routes=[Route("/", _homepage)])
    return AgentScoreGate(app, api_key="ask_test_key", **gate_kwargs)


def _mock_assess(decision: str = "allow", reasons: list[str] | None = None) -> respx.Route:
    return respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "decision": decision,
                "decision_reasons": reasons or [],
            },
        )
    )


class TestCreateSessionOnMissing:
    @respx.mock
    def test_creates_session_and_returns_403_with_session_data(self):
        respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))

        app = _make_app(
            create_session_on_missing=CreateSessionOnMissing(api_key="ask_session_key"),
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/")

        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "identity_verification_required"
        assert data["verify_url"] == "https://agentscore.sh/verify/sess_abc123"
        assert data["session_id"] == "sess_abc123"
        assert data["poll_secret"] == "ps_secret_456"
        assert data["agent_instructions"] == "Please complete identity verification at the verify_url."

    @respx.mock
    def test_session_request_uses_correct_api_key(self):
        route = respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))

        app = _make_app(
            create_session_on_missing=CreateSessionOnMissing(api_key="ask_session_key"),
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.get("/")

        assert route.call_count == 1
        request = route.calls[0].request
        assert request.headers["X-API-Key"] == "ask_session_key"

    @respx.mock
    def test_uses_custom_base_url(self):
        custom_url = "https://custom.api.example.com/v1/sessions"
        route = respx.post(custom_url).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))

        app = _make_app(
            create_session_on_missing=CreateSessionOnMissing(
                api_key="ask_session_key",
                base_url="https://custom.api.example.com",
            ),
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.get("/")

        assert route.call_count == 1

    @respx.mock
    def test_falls_back_to_missing_identity_on_session_api_error(self):
        respx.post(SESSIONS_URL).mock(return_value=httpx.Response(500))

        app = _make_app(
            create_session_on_missing=CreateSessionOnMissing(api_key="ask_session_key"),
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/")

        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "missing_identity"

    @respx.mock
    def test_falls_back_to_missing_identity_on_network_error(self):
        respx.post(SESSIONS_URL).mock(side_effect=httpx.ConnectError("connection refused"))

        app = _make_app(
            create_session_on_missing=CreateSessionOnMissing(api_key="ask_session_key"),
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/")

        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "missing_identity"

    @respx.mock
    def test_does_not_create_session_when_identity_is_present(self):
        assess_route = _mock_assess()
        session_route = respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))

        app = _make_app(
            create_session_on_missing=CreateSessionOnMissing(api_key="ask_session_key"),
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/", headers={"x-wallet-address": "0xabc"})

        assert resp.status_code == 200
        assert assess_route.call_count == 1
        assert session_route.call_count == 0

    @respx.mock
    def test_sends_first_class_fields_in_session_request(self):
        route = respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))

        app = _make_app(
            create_session_on_missing=CreateSessionOnMissing(
                api_key="ask_session_key",
                context="Wine purchase verification",
                product_name="Cabernet Reserve 2023",
            ),
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/")

        assert resp.status_code == 403
        assert route.call_count == 1
        body = json.loads(route.calls[0].request.content)
        assert body["context"] == "Wine purchase verification"
        assert body["product_name"] == "Cabernet Reserve 2023"

    @respx.mock
    def test_omits_unset_fields_from_session_request(self):
        route = respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))

        app = _make_app(
            create_session_on_missing=CreateSessionOnMissing(
                api_key="ask_session_key",
                context="Quick check",
            ),
        )
        client = TestClient(app, raise_server_exceptions=False)
        client.get("/")

        body = json.loads(route.calls[0].request.content)
        assert body["context"] == "Quick check"
        assert "product_name" not in body

    @respx.mock
    def test_fail_open_takes_precedence(self):
        session_route = respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))

        app = _make_app(
            fail_open=True,
            create_session_on_missing=CreateSessionOnMissing(api_key="ask_session_key"),
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/")

        assert resp.status_code == 200
        assert session_route.call_count == 0


CAPTURE_URL = "https://api.agentscore.sh/v1/credentials/wallets"


def _capture_app() -> Starlette:
    """Build a Starlette app whose handler invokes capture_wallet so we can verify the
    gate's context-stashing works end-to-end."""
    from starlette.responses import JSONResponse as SResp

    from agentscore_gate.middleware import capture_wallet

    async def purchase(request):
        await capture_wallet(request, "0xsigner", "evm", idempotency_key="pi_abc")
        return SResp({"ok": True})

    app = Starlette(routes=[Route("/purchase", purchase, methods=["POST"])])
    return AgentScoreGate(app, api_key="ask_test_key")


class TestCaptureWallet:
    @respx.mock
    def test_captures_when_operator_token_present(self):
        _mock_assess()
        capture_route = respx.post(CAPTURE_URL).mock(
            return_value=httpx.Response(200, json={"associated": True, "first_seen": True}),
        )
        app = _capture_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/purchase", headers={"X-Operator-Token": "opc_abc"})

        assert resp.status_code == 200
        assert capture_route.called
        body = json.loads(capture_route.calls[0].request.content.decode())
        assert body == {
            "operator_token": "opc_abc",
            "wallet_address": "0xsigner",
            "network": "evm",
            "idempotency_key": "pi_abc",
        }

    @respx.mock
    def test_no_ops_when_wallet_authenticated(self):
        _mock_assess()
        capture_route = respx.post(CAPTURE_URL).mock(
            return_value=httpx.Response(200, json={"associated": True, "first_seen": True}),
        )
        app = _capture_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/purchase", headers={"X-Wallet-Address": "0xwallet"})

        assert resp.status_code == 200
        assert capture_route.call_count == 0

    @respx.mock
    def test_no_ops_when_gate_did_not_run(self):
        """Calling capture_wallet on a request that never went through AgentScoreGate
        (no middleware installed) should silently no-op rather than crash."""
        import httpx as httpx_client  # avoid shadowing the module-level import
        from starlette.requests import Request as SReq

        from agentscore_gate.middleware import capture_wallet

        capture_route = respx.post(CAPTURE_URL).mock(
            return_value=httpx_client.Response(200, json={"associated": True, "first_seen": True}),
        )

        # Build a Request with a scope that has no state from our gate.
        scope: dict = {"type": "http", "headers": [], "method": "POST", "path": "/"}

        async def _receive() -> dict:
            return {"type": "http.request"}

        request = SReq(scope, _receive)

        import asyncio

        asyncio.get_event_loop().run_until_complete(
            capture_wallet(request, "0xsigner", "evm"),
        )
        assert capture_route.call_count == 0
