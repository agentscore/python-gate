"""Direct unit tests for GateClient internals."""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx

from agentscore_gate.client import GateClient


def _make_client(**kwargs) -> GateClient:
    defaults = {"api_key": "ask_test_key"}
    defaults.update(kwargs)
    return GateClient(**defaults)


class TestHeaders:
    def test_includes_user_agent(self):
        client = _make_client()
        headers = client._headers()
        assert "User-Agent" in headers
        assert "agentscore" in headers["User-Agent"].lower()

    def test_includes_authorization(self):
        client = _make_client(api_key="ask_my_secret")
        headers = client._headers()
        assert headers["Authorization"] == "Bearer ask_my_secret"


class TestCacheKey:
    def test_lowercases_address(self):
        client = _make_client()
        key = client._cache_key("0xABCDEF", "base")
        assert "0xabcdef" in key

    def test_chain_address_format(self):
        client = _make_client()
        key = client._cache_key("0xABC", "ethereum")
        assert key == "ethereum:0xabc"


class TestParseResponse:
    def test_missing_decision_allows(self):
        """When the decision field is absent, the request should be allowed."""
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {"score": 80}

        result = client._parse_response(resp)
        assert result.allow is True

    def test_deny_decision(self):
        """When decision is 'deny', result.allow should be False."""
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "deny",
            "decision_reasons": ["low_score"],
        }

        result = client._parse_response(resp)
        assert result.allow is False
        assert result.decision == "deny"
        assert "low_score" in result.reasons


class TestBuildBody:
    def test_includes_policy_when_set(self):
        client = _make_client(min_score=50, min_grade="B")
        body = client._build_body("0xabc", "base")
        assert body["address"] == "0xabc"
        assert body["chain"] == "base"
        assert "policy" in body
        assert body["policy"]["min_score"] == 50
        assert body["policy"]["min_grade"] == "B"

    def test_no_policy_when_empty(self):
        client = _make_client()
        body = client._build_body("0xabc", "base")
        assert "policy" not in body
