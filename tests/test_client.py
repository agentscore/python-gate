"""Direct unit tests for GateClient internals."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from agentscore_gate.client import GateClient, PaymentRequiredError


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

    def test_includes_api_key_header(self):
        client = _make_client(api_key="ask_my_secret")
        headers = client._headers()
        assert headers["X-API-Key"] == "ask_my_secret"


class TestCacheKey:
    def test_lowercases_address(self):
        client = _make_client()
        key = client._cache_key("0xABCDEF")
        assert key == "0xabcdef"

    def test_address_only(self):
        client = _make_client()
        key = client._cache_key("0xABC")
        assert key == "0xabc"


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
        client = _make_client(require_kyc=True)
        body = client._build_body("0xabc")
        assert body["address"] == "0xabc"
        assert "chain" not in body
        assert "policy" in body
        assert body["policy"]["require_kyc"] is True

    def test_no_policy_when_empty(self):
        client = _make_client()
        body = client._build_body("0xabc")
        assert "policy" not in body
        assert "chain" not in body


class TestParseResponse402:
    def test_raises_payment_required_error(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 402
        with pytest.raises(PaymentRequiredError):
            client._parse_response(resp)


ASSESS_URL = "https://api.agentscore.sh/v1/assess"


class TestCheckWithChain:
    @respx.mock
    def test_check_sends_chain_override(self):
        client = _make_client()
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"decision": "allow", "decision_reasons": []},
            )
        )

        client.check("0xABC", chain="ethereum")

        assert route.call_count == 1
        body = json.loads(route.calls[0].request.content)
        assert body["chain"] == "ethereum"

    @respx.mock
    def test_check_uses_client_chain_when_no_override(self):
        client = _make_client(chain="base")
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"decision": "allow", "decision_reasons": []},
            )
        )

        client.check("0xABC")

        body = json.loads(route.calls[0].request.content)
        assert body["chain"] == "base"


class TestCheckCaching:
    @respx.mock
    def test_second_call_uses_cache(self):
        client = _make_client()
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"decision": "allow", "decision_reasons": []},
            )
        )

        client.check("0xABC")
        client.check("0xABC")

        assert route.call_count == 1


class TestAcheckCaching:
    @pytest.mark.anyio
    @respx.mock
    async def test_second_call_uses_cache(self):
        client = _make_client()
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"decision": "allow", "decision_reasons": []},
            )
        )

        await client.acheck("0xABC")
        await client.acheck("0xABC")

        assert route.call_count == 1


class TestCheckFailOpen:
    def test_fail_open_stored_on_client(self):
        client = _make_client(fail_open=True)
        assert client.fail_open is True

    @respx.mock
    def test_check_raises_on_api_error(self):
        client = _make_client(fail_open=True)
        respx.post(ASSESS_URL).mock(return_value=httpx.Response(500))

        with pytest.raises(RuntimeError, match="AgentScore API returned 500"):
            client.check("0xABC")


class TestCompliancePolicyFields:
    def test_build_body_includes_require_kyc(self):
        client = _make_client(require_kyc=True)
        body = client._build_body("0xabc")
        assert body["policy"]["require_kyc"] is True

    def test_build_body_includes_require_sanctions_clear(self):
        client = _make_client(require_sanctions_clear=True)
        body = client._build_body("0xabc")
        assert body["policy"]["require_sanctions_clear"] is True

    def test_build_body_includes_min_age(self):
        client = _make_client(min_age=90)
        body = client._build_body("0xabc")
        assert body["policy"]["min_age"] == 90

    def test_build_body_includes_blocked_jurisdictions(self):
        client = _make_client(blocked_jurisdictions=["KP", "IR"])
        body = client._build_body("0xabc")
        assert body["policy"]["blocked_jurisdictions"] == ["KP", "IR"]

    def test_build_body_includes_require_entity_type(self):
        client = _make_client(require_entity_type="agent")
        body = client._build_body("0xabc")
        assert body["policy"]["require_entity_type"] == "agent"

    def test_build_body_includes_all_compliance_fields(self):
        client = _make_client(
            require_kyc=True,
            require_sanctions_clear=True,
            min_age=30,
            blocked_jurisdictions=["KP"],
            require_entity_type="agent",
        )
        body = client._build_body("0xabc")
        assert body["policy"] == {
            "require_kyc": True,
            "require_sanctions_clear": True,
            "min_age": 30,
            "blocked_jurisdictions": ["KP"],
            "require_entity_type": "agent",
        }


class TestOperatorVerificationParsing:
    def test_parses_operator_verification_from_response(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "deny",
            "decision_reasons": ["kyc_required"],
            "operator_verification": {
                "level": "kyc_verified",
                "operator_type": "business",
                "claimed_at": "2024-06-01T00:00:00Z",
                "verified_at": "2024-06-15T00:00:00Z",
            },
        }

        result = client._parse_response(resp)
        assert result.operator_verification is not None
        assert result.operator_verification.level == "kyc_verified"
        assert result.operator_verification.operator_type == "business"
        assert result.operator_verification.claimed_at == "2024-06-01T00:00:00Z"
        assert result.operator_verification.verified_at == "2024-06-15T00:00:00Z"

    def test_operator_verification_is_none_when_absent(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "allow",
            "decision_reasons": [],
        }

        result = client._parse_response(resp)
        assert result.operator_verification is None


class TestVerifyUrlParsing:
    def test_parses_verify_url_from_response(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "deny",
            "decision_reasons": ["kyc_required"],
            "verify_url": "https://agentscore.sh/verify/abc123",
        }

        result = client._parse_response(resp)
        assert result.verify_url == "https://agentscore.sh/verify/abc123"

    def test_verify_url_is_none_when_absent(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "allow",
            "decision_reasons": [],
        }

        result = client._parse_response(resp)
        assert result.verify_url is None

    def test_parses_resolved_operator_from_response(self):
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "deny",
            "decision_reasons": ["kyc_required"],
            "resolved_operator": "0xoperator456",
        }

        result = client._parse_response(resp)
        assert result.resolved_operator == "0xoperator456"


class TestComplianceDenyIntegration:
    @respx.mock
    def test_full_compliance_deny_flow(self):
        """Integration test: full middleware flow with compliance deny."""
        compliance_response = {
            "decision": "deny",
            "decision_reasons": ["kyc_required", "sanctions_check_pending"],
            "score": {"value": 72, "grade": "C", "status": "scored"},
            "operator_verification": {
                "level": "none",
                "operator_type": None,
                "claimed_at": None,
                "verified_at": None,
            },
            "verify_url": "https://agentscore.sh/verify/xyz789",
            "resolved_operator": "0xoperator456",
            "chains": [
                {
                    "chain": "base",
                    "classification": {"entity_type": "wallet"},
                    "activity": {},
                    "identity": {},
                }
            ],
        }

        route = respx.post(ASSESS_URL).mock(return_value=httpx.Response(200, json=compliance_response))

        client = _make_client(
            require_kyc=True,
            require_sanctions_clear=True,
        )
        result = client.check("0xABC")

        assert result.allow is False
        assert result.decision == "deny"
        assert "kyc_required" in result.reasons
        assert "sanctions_check_pending" in result.reasons
        assert result.verify_url == "https://agentscore.sh/verify/xyz789"
        assert result.operator_verification is not None
        assert result.operator_verification.level == "none"
        assert result.resolved_operator == "0xoperator456"

        body = json.loads(route.calls[0].request.content)
        assert body["policy"]["require_kyc"] is True
        assert body["policy"]["require_sanctions_clear"] is True


class TestAgentIdentityDataclass:
    def test_construct_with_address_only(self):
        from agentscore_gate.types import AgentIdentity

        identity = AgentIdentity(address="0xabc")
        assert identity.address == "0xabc"
        assert identity.operator_token is None

    def test_construct_with_operator_token_only(self):
        from agentscore_gate.types import AgentIdentity

        identity = AgentIdentity(operator_token="opc_test")
        assert identity.address is None
        assert identity.operator_token == "opc_test"

    def test_construct_with_both(self):
        from agentscore_gate.types import AgentIdentity

        identity = AgentIdentity(address="0xabc", operator_token="opc_test")
        assert identity.address == "0xabc"
        assert identity.operator_token == "opc_test"

    def test_construct_empty_defaults_to_none(self):
        from agentscore_gate.types import AgentIdentity

        identity = AgentIdentity()
        assert identity.address is None
        assert identity.operator_token is None


class TestCheckIdentity:
    @respx.mock
    def test_check_identity_sends_operator_token(self):
        from agentscore_gate.types import AgentIdentity

        client = _make_client()
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"decision": "allow", "decision_reasons": []},
            )
        )

        identity = AgentIdentity(operator_token="opc_abc")
        client.check_identity(identity)

        body = json.loads(route.calls[0].request.content)
        assert body["operator_token"] == "opc_abc"
        assert "address" not in body

    @respx.mock
    def test_check_identity_sends_address(self):
        from agentscore_gate.types import AgentIdentity

        client = _make_client()
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"decision": "allow", "decision_reasons": []},
            )
        )

        identity = AgentIdentity(address="0xABC")
        client.check_identity(identity)

        body = json.loads(route.calls[0].request.content)
        assert body["address"] == "0xABC"
        assert "operator_token" not in body

    @respx.mock
    def test_check_identity_sends_both(self):
        from agentscore_gate.types import AgentIdentity

        client = _make_client()
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"decision": "allow", "decision_reasons": []},
            )
        )

        identity = AgentIdentity(address="0xABC", operator_token="opc_both")
        client.check_identity(identity)

        body = json.loads(route.calls[0].request.content)
        assert body["address"] == "0xABC"
        assert body["operator_token"] == "opc_both"


class TestAcheckIdentity:
    @pytest.mark.anyio
    @respx.mock
    async def test_acheck_identity_sends_operator_token(self):
        from agentscore_gate.types import AgentIdentity

        client = _make_client()
        route = respx.post(ASSESS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"decision": "allow", "decision_reasons": []},
            )
        )

        identity = AgentIdentity(operator_token="opc_async")
        await client.acheck_identity(identity)

        body = json.loads(route.calls[0].request.content)
        assert body["operator_token"] == "opc_async"
        assert "address" not in body


class TestCacheKeyIdentity:
    def test_cache_key_prefers_operator_token(self):
        client = _make_client()
        key = client._cache_key(address="0xABC", operator_token="OPC_TEST")
        assert key == "opc_test"

    def test_cache_key_falls_back_to_address(self):
        client = _make_client()
        key = client._cache_key(address="0xABC")
        assert key == "0xabc"

    def test_cache_key_lowercases_operator_token(self):
        client = _make_client()
        key = client._cache_key(operator_token="OPC_UPPER")
        assert key == "opc_upper"


class TestBuildBodyIdentity:
    def test_build_body_with_operator_token_only(self):
        client = _make_client()
        body = client._build_body(operator_token="opc_test")
        assert body["operator_token"] == "opc_test"
        assert "address" not in body

    def test_build_body_with_both(self):
        client = _make_client()
        body = client._build_body(address="0xabc", operator_token="opc_test")
        assert body["address"] == "0xabc"
        assert body["operator_token"] == "opc_test"

    def test_build_body_address_only_backwards_compat(self):
        client = _make_client()
        body = client._build_body("0xabc")
        assert body["address"] == "0xabc"
        assert "operator_token" not in body
