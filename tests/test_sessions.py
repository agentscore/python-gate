"""Tests for the shared session-creation helpers in agentscore_gate.sessions."""

from __future__ import annotations

import httpx
import pytest
import respx

from agentscore_gate.sessions import (
    CreateSessionOnMissing,
    try_create_session_denial_reason,
    try_create_session_denial_reason_sync,
)

SESSIONS_URL = "https://api.agentscore.sh/v1/sessions"
SESSION_RESPONSE = {
    "session_id": "sess_abc",
    "verify_url": "https://agentscore.sh/verify/sess_abc",
    "poll_secret": "ps_secret",
    "agent_instructions": "please verify",
}


class TestSyncHelper:
    @respx.mock
    def test_returns_denial_reason_on_success(self):
        respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))
        reason = try_create_session_denial_reason_sync(
            CreateSessionOnMissing(api_key="ask_test"),
            user_agent="agentscore-gate/1.0",
        )
        assert reason is not None
        assert reason.code == "identity_verification_required"
        assert reason.session_id == "sess_abc"
        assert reason.verify_url == "https://agentscore.sh/verify/sess_abc"
        assert reason.poll_secret == "ps_secret"
        assert reason.agent_instructions == "please verify"

    @respx.mock
    def test_returns_none_on_server_error(self):
        respx.post(SESSIONS_URL).mock(return_value=httpx.Response(500, text="oops"))
        reason = try_create_session_denial_reason_sync(
            CreateSessionOnMissing(api_key="ask_test"),
            user_agent="agentscore-gate/1.0",
        )
        assert reason is None

    @respx.mock
    def test_returns_none_on_network_error(self):
        respx.post(SESSIONS_URL).mock(side_effect=httpx.ConnectError("boom"))
        reason = try_create_session_denial_reason_sync(
            CreateSessionOnMissing(api_key="ask_test"),
            user_agent="agentscore-gate/1.0",
        )
        assert reason is None

    @respx.mock
    def test_forwards_context_and_product_name(self):
        route = respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))
        try_create_session_denial_reason_sync(
            CreateSessionOnMissing(
                api_key="ask_test",
                context="purchase_flow",
                product_name="Martin Estate",
            ),
            user_agent="agentscore-gate/1.0",
        )
        import json

        body = json.loads(route.calls[0].request.content)
        assert body["context"] == "purchase_flow"
        assert body["product_name"] == "Martin Estate"

    @respx.mock
    def test_omits_context_and_product_name_when_not_provided(self):
        route = respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))
        try_create_session_denial_reason_sync(
            CreateSessionOnMissing(api_key="ask_test"),
            user_agent="agentscore-gate/1.0",
        )
        import json

        body = json.loads(route.calls[0].request.content)
        assert "context" not in body
        assert "product_name" not in body

    @respx.mock
    def test_forwards_api_key_and_user_agent(self):
        route = respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))
        try_create_session_denial_reason_sync(
            CreateSessionOnMissing(api_key="ask_my_key"),
            user_agent="myapp/1.0",
        )
        headers = route.calls[0].request.headers
        assert headers["X-API-Key"] == "ask_my_key"
        assert headers["User-Agent"] == "myapp/1.0"

    @respx.mock
    def test_respects_custom_base_url(self):
        custom_url = "https://staging.agentscore.sh/v1/sessions"
        route = respx.post(custom_url).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))
        try_create_session_denial_reason_sync(
            CreateSessionOnMissing(api_key="ask_test", base_url="https://staging.agentscore.sh"),
            user_agent="agentscore-gate/1.0",
        )
        assert route.called


class TestAsyncHelper:
    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_denial_reason_on_success(self):
        respx.post(SESSIONS_URL).mock(return_value=httpx.Response(200, json=SESSION_RESPONSE))
        reason = await try_create_session_denial_reason(
            CreateSessionOnMissing(api_key="ask_test"),
            user_agent="agentscore-gate/1.0",
        )
        assert reason is not None
        assert reason.session_id == "sess_abc"

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_none_on_network_error(self):
        respx.post(SESSIONS_URL).mock(side_effect=httpx.ConnectError("boom"))
        reason = await try_create_session_denial_reason(
            CreateSessionOnMissing(api_key="ask_test"),
            user_agent="agentscore-gate/1.0",
        )
        assert reason is None
