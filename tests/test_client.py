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

    def test_parses_score(self):
        """Score fields are parsed into a ScoreDetail dataclass."""
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "allow",
            "decision_reasons": [],
            "score": {
                "value": 85,
                "grade": "B",
                "scored_at": "2026-03-28T00:00:00Z",
                "status": "scored",
                "version": "v1",
            },
        }

        result = client._parse_response(resp)
        assert result.score is not None
        assert result.score.value == 85
        assert result.score.grade == "B"
        assert result.score.status == "scored"
        assert result.score.scored_at == "2026-03-28T00:00:00Z"
        assert result.score.version == "v1"
        assert result.score.confidence is None
        assert result.score.dimensions is None

    def test_parses_activity(self):
        """Activity fields are parsed into an Activity dataclass."""
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "allow",
            "decision_reasons": [],
            "chains": [
                {
                    "chain": "base",
                    "activity": {
                        "total_verified_transactions": 10,
                        "total_candidate_transactions": 25,
                        "counterparties_count": 5,
                        "active_days": 30,
                        "active_months": 3,
                        "as_verified_payer": 4,
                        "as_verified_payee": 6,
                        "as_candidate_payer": 12,
                        "as_candidate_payee": 13,
                        "first_verified_tx_at": "2025-01-01T00:00:00Z",
                        "last_verified_tx_at": "2026-03-01T00:00:00Z",
                    },
                },
            ],
        }

        result = client._parse_response(resp)
        assert result.activity is not None
        assert result.activity.total_verified_transactions == 10
        assert result.activity.counterparties_count == 5
        assert result.activity.active_days == 30
        assert result.activity.as_verified_payer == 4
        assert result.activity.first_verified_tx_at == "2025-01-01T00:00:00Z"

    def test_parses_classification(self):
        """Classification fields are parsed into a Classification dataclass."""
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "allow",
            "decision_reasons": [],
            "chains": [
                {
                    "chain": "base",
                    "classification": {
                        "entity_type": "agent",
                        "confidence": 0.95,
                        "is_known": True,
                        "is_known_erc8004_agent": True,
                        "has_verified_payment_activity": True,
                        "has_candidate_payment_activity": True,
                        "reasons": ["registered_erc8004"],
                    },
                },
            ],
        }

        result = client._parse_response(resp)
        assert result.classification is not None
        assert result.classification.entity_type == "agent"
        assert result.classification.is_known_erc8004_agent is True
        assert result.classification.has_verified_payment_activity is True
        assert "registered_erc8004" in result.classification.reasons

    def test_parses_identity(self):
        """Identity fields are parsed into an Identity dataclass."""
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {
            "decision": "allow",
            "decision_reasons": [],
            "chains": [
                {
                    "chain": "base",
                    "identity": {
                        "ens_name": "agent.eth",
                        "github_url": "https://github.com/example",
                        "website_url": "https://example.com",
                    },
                },
            ],
        }

        result = client._parse_response(resp)
        assert result.identity is not None
        assert result.identity.ens_name == "agent.eth"
        assert result.identity.github_url == "https://github.com/example"

    def test_missing_reputation_fields_are_none(self):
        """When reputation fields are absent, typed fields are None."""
        client = _make_client()
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.is_success = True
        resp.json.return_value = {"decision": "allow", "decision_reasons": []}

        result = client._parse_response(resp)
        assert result.score is None
        assert result.activity is None
        assert result.classification is None
        assert result.identity is None


class TestBuildBody:
    def test_includes_policy_when_set(self):
        client = _make_client(min_score=50, min_grade="B")
        body = client._build_body("0xabc")
        assert body["address"] == "0xabc"
        assert "chain" not in body
        assert "policy" in body
        assert body["policy"]["min_score"] == 50
        assert body["policy"]["min_grade"] == "B"

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
            min_grade="B",
            min_score=70,
            require_kyc=True,
            require_sanctions_clear=True,
            min_age=30,
            blocked_jurisdictions=["KP"],
            require_entity_type="agent",
        )
        body = client._build_body("0xabc")
        assert body["policy"] == {
            "min_grade": "B",
            "min_score": 70,
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
