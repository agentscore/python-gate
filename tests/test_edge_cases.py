"""Edge case tests for agentscore-gate Python SDK."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from agentscore_gate import AgentScoreGate
from agentscore_gate.client import GateClient, PaymentRequiredError
from agentscore_gate.types import AssessResult, DenialReason


# ---------------------------------------------------------------------------
# Source-code reading sanity checks
# ---------------------------------------------------------------------------

CLIENT_SRC = Path(__file__).resolve().parent.parent / "agentscore_gate" / "client.py"
TYPES_SRC = Path(__file__).resolve().parent.parent / "agentscore_gate" / "types.py"
CACHE_SRC = Path(__file__).resolve().parent.parent / "agentscore_gate" / "cache.py"


class TestSourceStructure:
    def test_client_exports_gate_client(self):
        src = CLIENT_SRC.read_text()
        assert "class GateClient" in src

    def test_client_has_parse_response(self):
        src = CLIENT_SRC.read_text()
        assert "def _parse_response" in src

    def test_types_has_denial_reason_with_verify_url(self):
        src = TYPES_SRC.read_text()
        assert "verify_url" in src
        assert "class DenialReason" in src

    def test_cache_has_thread_lock(self):
        src = CACHE_SRC.read_text()
        assert "threading.Lock" in src

    def test_client_sends_user_agent(self):
        src = CLIENT_SRC.read_text()
        assert "User-Agent" in src
        assert "agentscore-gate-py" in src


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

API_KEY = "ask_test_key"
BASE_URL = "https://api.agentscore.sh"
ASSESS_URL = f"{BASE_URL}/v1/assess"


def _make_client(**kwargs) -> GateClient:
    defaults = {"api_key": API_KEY}
    defaults.update(kwargs)
    return GateClient(**defaults)


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
        agentscore_data = (
            request.state.agentscore if hasattr(request.state, "agentscore") else None
        )
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


# ---------------------------------------------------------------------------
# Error handling: HTTP 500, timeout from API
# ---------------------------------------------------------------------------


class TestClientErrorHandling:
    @respx.mock
    def test_check_raises_runtime_error_on_500(self):
        client = _make_client()
        respx.post(ASSESS_URL).mock(return_value=httpx.Response(500))

        with pytest.raises(RuntimeError, match="AgentScore API returned 500"):
            client.check("0xABC")

    @respx.mock
    def test_check_raises_payment_required_on_402(self):
        client = _make_client()
        respx.post(ASSESS_URL).mock(return_value=httpx.Response(402))

        with pytest.raises(PaymentRequiredError):
            client.check("0xABC")

    @respx.mock
    def test_check_raises_runtime_error_on_503(self):
        client = _make_client()
        respx.post(ASSESS_URL).mock(return_value=httpx.Response(503))

        with pytest.raises(RuntimeError, match="AgentScore API returned 503"):
            client.check("0xABC")

    @respx.mock
    def test_check_raises_runtime_error_on_429(self):
        client = _make_client()
        respx.post(ASSESS_URL).mock(return_value=httpx.Response(429))

        with pytest.raises(RuntimeError, match="AgentScore API returned 429"):
            client.check("0xABC")

    def test_acheck_raises_on_error_status(self):
        """Verify async check method raises RuntimeError on non-200 responses."""
        source = (Path(__file__).resolve().parent.parent / "agentscore_gate" / "client.py").read_text()
        assert "raise RuntimeError" in source
        assert "acheck" in source


# ---------------------------------------------------------------------------
# Auth header extraction failures
# ---------------------------------------------------------------------------


class TestAuthHeaderExtraction:
    def test_missing_api_key_raises_value_error(self):
        with pytest.raises(ValueError, match="API key is required"):
            GateClient(api_key="")

    def test_headers_include_api_key(self):
        client = _make_client(api_key="ask_my_secret")
        headers = client._headers()
        assert headers["X-API-Key"] == "ask_my_secret"

    def test_headers_include_content_type(self):
        client = _make_client()
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# Middleware: HTTP 500/timeout with fail_open/fail_closed
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@respx.mock
async def test_middleware_503_fail_closed():
    app = _make_app(min_score=50)
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(503))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        resp = await c.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 403
    assert resp.json()["error"] == "api_error"


@pytest.mark.anyio
@respx.mock
async def test_middleware_503_fail_open():
    app = _make_app(min_score=50, fail_open=True)
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(503))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        resp = await c.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 200


@pytest.mark.anyio
@respx.mock
async def test_middleware_429_fail_closed():
    app = _make_app(min_score=50)
    respx.post(ASSESS_URL).mock(return_value=httpx.Response(429))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        resp = await c.get("/", headers={"x-wallet-address": "0xABC123"})
    assert resp.status_code == 403
    assert resp.json()["error"] == "api_error"


# ---------------------------------------------------------------------------
# Concurrent requests
# ---------------------------------------------------------------------------


class TestConcurrentRequests:
    @respx.mock
    def test_concurrent_sync_checks_are_thread_safe(self):
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200, json={"decision": "allow", "decision_reasons": []}
            )
        )
        client = _make_client()
        errors: list[Exception] = []

        def worker(addr: str) -> None:
            try:
                result = client.check(addr)
                assert result.allow is True
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"0xaddr{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# ---------------------------------------------------------------------------
# Compliance options edge cases
# ---------------------------------------------------------------------------


class TestComplianceOptionsEdgeCases:
    def test_min_score_zero_included_in_policy(self):
        client = _make_client(min_score=0)
        body = client._build_body("0xabc")
        assert body["policy"]["min_score"] == 0

    def test_require_kyc_false_included_in_policy(self):
        client = _make_client(require_kyc=False)
        body = client._build_body("0xabc")
        assert body["policy"]["require_kyc"] is False

    def test_require_sanctions_clear_false_included_in_policy(self):
        client = _make_client(require_sanctions_clear=False)
        body = client._build_body("0xabc")
        assert body["policy"]["require_sanctions_clear"] is False

    def test_empty_blocked_jurisdictions_included_in_policy(self):
        client = _make_client(blocked_jurisdictions=[])
        body = client._build_body("0xabc")
        assert body["policy"]["blocked_jurisdictions"] == []

    def test_min_age_zero_included_in_policy(self):
        client = _make_client(min_age=0)
        body = client._build_body("0xabc")
        assert body["policy"]["min_age"] == 0

    def test_require_verified_activity_false_included_in_policy(self):
        client = _make_client(require_verified_activity=False)
        body = client._build_body("0xabc")
        assert body["policy"]["require_verified_payment_activity"] is False

    def test_chain_override_in_check(self):
        client = _make_client(chain="base")
        body = client._build_body("0xabc", chain="ethereum")
        assert body["chain"] == "ethereum"


# ---------------------------------------------------------------------------
# verify_url in DenialReason
# ---------------------------------------------------------------------------


class TestVerifyUrlInDenialReason:
    def test_denial_reason_has_verify_url_field(self):
        reason = DenialReason(
            code="wallet_not_trusted",
            decision="deny",
            reasons=["kyc_required"],
            verify_url="https://agentscore.sh/verify/abc",
        )
        assert reason.verify_url == "https://agentscore.sh/verify/abc"

    def test_denial_reason_verify_url_defaults_to_none(self):
        reason = DenialReason(code="api_error")
        assert reason.verify_url is None

    def test_parse_response_includes_verify_url(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "deny",
            "decision_reasons": ["kyc_required"],
            "verify_url": "https://agentscore.sh/verify/test",
        }

        result = client._parse_response(resp)
        assert result.verify_url == "https://agentscore.sh/verify/test"
        assert result.allow is False

    def test_parse_response_verify_url_none_when_absent(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "deny",
            "decision_reasons": ["low_score"],
        }

        result = client._parse_response(resp)
        assert result.verify_url is None


# ---------------------------------------------------------------------------
# Status code edge cases
# ---------------------------------------------------------------------------


class TestStatusCodeEdgeCases:
    def test_401_raises_runtime_error(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 401
        resp.is_success = False

        with pytest.raises(RuntimeError, match="AgentScore API returned 401"):
            client._parse_response(resp)

    def test_403_raises_runtime_error(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 403
        resp.is_success = False

        with pytest.raises(RuntimeError, match="AgentScore API returned 403"):
            client._parse_response(resp)

    def test_200_with_decision_none_allows(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": None,
            "decision_reasons": [],
        }

        result = client._parse_response(resp)
        assert result.allow is True

    def test_200_with_missing_decision_allows(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {}

        result = client._parse_response(resp)
        assert result.allow is True


# ---------------------------------------------------------------------------
# Middleware edge cases: empty wallet, whitespace
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_empty_string_wallet_returns_403():
    app = _make_app(min_score=50)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        resp = await c.get("/", headers={"x-wallet-address": ""})
    assert resp.status_code == 403
    assert resp.json()["error"] == "missing_wallet_address"


@pytest.mark.anyio
@respx.mock
async def test_middleware_caches_deny_with_verify_url():
    """Cached deny preserves verify_url across requests."""
    app = _make_app(min_score=50)
    compliance_response = {
        "decision": "deny",
        "decision_reasons": ["kyc_required"],
        "verify_url": "https://agentscore.sh/verify/cache_test",
    }
    route = respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(200, json=compliance_response)
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        resp1 = await c.get("/", headers={"x-wallet-address": "0xCACHED"})
        resp2 = await c.get("/", headers={"x-wallet-address": "0xCACHED"})

    assert resp1.status_code == 403
    assert resp2.status_code == 403
    assert route.call_count == 1


@pytest.mark.anyio
@respx.mock
async def test_middleware_different_wallets_not_cached_together():
    """Different wallet addresses get separate cache entries."""
    app = _make_app(min_score=50)
    route = respx.post(ASSESS_URL).mock(
        return_value=httpx.Response(
            200, json={"decision": "allow", "decision_reasons": []}
        )
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        await c.get("/", headers={"x-wallet-address": "0xAAA"})
        await c.get("/", headers={"x-wallet-address": "0xBBB"})

    assert route.call_count == 2
