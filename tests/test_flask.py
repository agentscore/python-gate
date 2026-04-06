"""Tests for the Flask integration."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from flask import Flask

from agentscore_gate.client import PaymentRequiredError
from agentscore_gate.flask import agentscore_gate
from agentscore_gate.types import AssessResult


def _make_app(**gate_kwargs: object) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    agentscore_gate(app, api_key="test-key", **gate_kwargs)

    @app.route("/")
    def index():
        from flask import g

        return {"ok": True, "agentscore": getattr(g, "agentscore", None)}

    return app


def _mock_result(allow: bool = True, decision: str | None = "allow") -> AssessResult:
    return AssessResult(allow=allow, decision=decision, reasons=[], raw={"score": 80, "grade": "B"})


class TestFlaskGate:
    """Flask adapter tests."""

    def test_allows_trusted_wallet(self) -> None:
        app = _make_app()
        with patch("agentscore_gate.flask.GateClient.check", return_value=_mock_result()):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["ok"] is True
            assert data["agentscore"] is not None

    def test_blocks_untrusted_wallet(self) -> None:
        app = _make_app()
        result = AssessResult(allow=False, decision="deny", reasons=["score_too_low"], raw={})
        with patch("agentscore_gate.flask.GateClient.check", return_value=result):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 403
            data = resp.get_json()
            assert data["error"] == "wallet_not_trusted"

    def test_missing_wallet_returns_403(self) -> None:
        app = _make_app()
        client = app.test_client()
        resp = client.get("/")
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["error"] == "missing_wallet_address"

    def test_missing_wallet_fail_open(self) -> None:
        app = _make_app(fail_open=True)
        client = app.test_client()
        resp = client.get("/")
        assert resp.status_code == 200

    def test_api_error_fail_open(self) -> None:
        app = _make_app(fail_open=True)
        with patch("agentscore_gate.flask.GateClient.check", side_effect=RuntimeError("timeout")):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 200

    def test_api_error_fail_closed(self) -> None:
        app = _make_app()
        with patch("agentscore_gate.flask.GateClient.check", side_effect=RuntimeError("timeout")):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 403
            data = resp.get_json()
            assert data["error"] == "api_error"

    def test_payment_required_fail_open(self) -> None:
        app = _make_app(fail_open=True)
        with patch(
            "agentscore_gate.flask.GateClient.check",
            side_effect=PaymentRequiredError,
        ):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 200

    def test_payment_required_fail_closed(self) -> None:
        app = _make_app()
        with patch(
            "agentscore_gate.flask.GateClient.check",
            side_effect=PaymentRequiredError,
        ):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 403
            data = resp.get_json()
            assert data["error"] == "payment_required"

    def test_extract_chain_passed_to_api(self) -> None:
        def custom_extract_chain(_request):
            return "ethereum"

        app = _make_app(extract_chain=custom_extract_chain)
        with patch("agentscore_gate.flask.GateClient.check", return_value=_mock_result()) as mock_check:
            client = app.test_client()
            client.get("/", headers={"x-wallet-address": "0xabc"})
            mock_check.assert_called_once_with("0xabc", "ethereum")

    def test_custom_extract_address_returning_none(self) -> None:
        def always_none(_request):
            return None

        app = _make_app(extract_address=always_none)
        client = app.test_client()
        resp = client.get("/", headers={"x-wallet-address": "0xabc"})
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["error"] == "missing_wallet_address"

    def test_custom_on_denied_returning_wrong_type(self) -> None:
        def bad_on_denied(_request, _reason):
            return "not-a-tuple"

        app = _make_app(on_denied=bad_on_denied)
        client = app.test_client()
        with pytest.raises(TypeError, match="on_denied must return a"):
            client.get("/")

    def test_requires_api_key(self) -> None:
        with pytest.raises(ValueError, match="API key is required"):
            app = Flask(__name__)
            agentscore_gate(app, api_key="")

    def test_compliance_params_passed_to_client(self) -> None:
        with patch("agentscore_gate.flask.GateClient") as mock_cls:
            mock_cls.return_value = mock_cls
            mock_cls.fail_open = False
            app = Flask(__name__)
            agentscore_gate(
                app,
                api_key="test-key",
                require_kyc=True,
                require_sanctions_clear=True,
                min_age=90,
                blocked_jurisdictions=["KP", "IR"],
                require_entity_type="agent",
            )
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs["require_kyc"] is True
            assert call_kwargs["require_sanctions_clear"] is True
            assert call_kwargs["min_age"] == 90
            assert call_kwargs["blocked_jurisdictions"] == ["KP", "IR"]
            assert call_kwargs["require_entity_type"] == "agent"

    def test_deny_includes_compliance_reasons(self) -> None:
        app = _make_app()
        result = AssessResult(
            allow=False,
            decision="deny",
            reasons=["kyc_required", "sanctions_check_pending"],
            raw={
                "verify_url": "https://agentscore.sh/verify/abc123",
                "operator_verification": {"level": "none"},
            },
        )
        with patch("agentscore_gate.flask.GateClient.check", return_value=result):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 403
            data = resp.get_json()
            assert data["error"] == "wallet_not_trusted"
            assert "kyc_required" in data["reasons"]
            assert "sanctions_check_pending" in data["reasons"]

    def test_allow_with_operator_verification_attaches_to_g(self) -> None:
        app = _make_app()
        raw = {
            "score": 80,
            "operator_verification": {
                "level": "kyc_verified",
                "operator_type": "business",
                "claimed_at": "2024-06-01T00:00:00Z",
                "verified_at": "2024-06-15T00:00:00Z",
            },
        }
        result = AssessResult(allow=True, decision="allow", reasons=[], raw=raw)
        with patch("agentscore_gate.flask.GateClient.check", return_value=result):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["agentscore"]["operator_verification"]["level"] == "kyc_verified"

    def test_verify_url_available_in_raw_on_deny(self) -> None:
        app = _make_app()
        raw = {
            "decision": "deny",
            "verify_url": "https://agentscore.sh/verify/abc123",
        }
        result = AssessResult(allow=False, decision="deny", reasons=["kyc_required"], raw=raw)
        with patch("agentscore_gate.flask.GateClient.check", return_value=result):
            client = app.test_client()
            resp = client.get("/", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 403
            data = resp.get_json()
            assert data["error"] == "wallet_not_trusted"
