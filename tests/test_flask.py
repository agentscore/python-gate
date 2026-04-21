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
        assert data["error"] == "missing_identity"

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
        with patch("agentscore_gate.flask.GateClient.check_identity", return_value=_mock_result()) as mock_check:
            client = app.test_client()
            client.get("/", headers={"x-wallet-address": "0xabc"})
            call_args = mock_check.call_args
            assert call_args[0][0].address == "0xabc"
            assert call_args[0][1] == "ethereum"

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
            )
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs["require_kyc"] is True
            assert call_kwargs["require_sanctions_clear"] is True
            assert call_kwargs["min_age"] == 90
            assert call_kwargs["blocked_jurisdictions"] == ["KP", "IR"]

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


class TestFlaskCreateSessionOnMissing:
    """Flask adapter's create_session_on_missing support."""

    def test_creates_session_and_returns_403_with_session_data(self) -> None:
        from agentscore_gate.sessions import CreateSessionOnMissing
        from agentscore_gate.types import DenialReason

        app = _make_app(create_session_on_missing=CreateSessionOnMissing(api_key="ask_session"))
        session_reason = DenialReason(
            code="identity_verification_required",
            verify_url="https://agentscore.sh/verify/sess_abc",
            session_id="sess_abc",
            poll_secret="ps_secret",
            agent_instructions="please verify",
        )
        with patch(
            "agentscore_gate.flask.try_create_session_denial_reason_sync",
            return_value=session_reason,
        ):
            client = app.test_client()
            resp = client.get("/")
            assert resp.status_code == 403
            data = resp.get_json()
            assert data["error"] == "identity_verification_required"
            assert data["session_id"] == "sess_abc"
            assert data["verify_url"] == "https://agentscore.sh/verify/sess_abc"
            assert data["poll_secret"] == "ps_secret"
            assert data["agent_instructions"] == "please verify"

    def test_falls_back_to_missing_identity_on_session_helper_failure(self) -> None:
        from agentscore_gate.sessions import CreateSessionOnMissing

        app = _make_app(create_session_on_missing=CreateSessionOnMissing(api_key="ask_session"))
        with patch(
            "agentscore_gate.flask.try_create_session_denial_reason_sync",
            return_value=None,
        ):
            client = app.test_client()
            resp = client.get("/")
            assert resp.status_code == 403
            data = resp.get_json()
            assert data["error"] == "missing_identity"


class TestFlaskIdentityModel:
    """Flask adapter identity model tests."""

    def test_default_extract_identity_returns_operator_token(self) -> None:
        from agentscore_gate.flask import _default_extract_identity

        class FakeRequest:
            headers = {"x-operator-token": "opc_flask", "x-wallet-address": "0xabc"}

        identity = _default_extract_identity(FakeRequest())
        assert identity is not None
        assert identity.operator_token == "opc_flask"
        assert identity.address == "0xabc"

    def test_default_extract_identity_address_only(self) -> None:
        from agentscore_gate.flask import _default_extract_identity

        class FakeRequest:
            headers = {"x-wallet-address": "0xabc"}

        identity = _default_extract_identity(FakeRequest())
        assert identity is not None
        assert identity.address == "0xabc"
        assert identity.operator_token is None

    def test_default_extract_identity_returns_none_when_empty(self) -> None:
        from agentscore_gate.flask import _default_extract_identity

        class FakeRequest:
            headers = {}

        identity = _default_extract_identity(FakeRequest())
        assert identity is None

    def test_missing_identity_returns_403(self) -> None:
        app = _make_app()
        client = app.test_client()
        resp = client.get("/")
        assert resp.status_code == 403
        data = resp.get_json()
        assert data["error"] == "missing_identity"

    def test_missing_identity_fail_open(self) -> None:
        app = _make_app(fail_open=True)
        client = app.test_client()
        resp = client.get("/")
        assert resp.status_code == 200

    def test_operator_token_header_calls_check_identity(self) -> None:
        app = _make_app()
        with patch("agentscore_gate.flask.GateClient.check_identity", return_value=_mock_result()) as mock_check:
            client = app.test_client()
            resp = client.get("/", headers={"x-operator-token": "opc_flask_test"})
            assert resp.status_code == 200
            call_args = mock_check.call_args
            identity = call_args[0][0]
            assert identity.operator_token == "opc_flask_test"


def _make_capture_app() -> Flask:
    """Flask app whose handler calls capture_wallet so we can verify gate-state stash."""
    from agentscore_gate.flask import agentscore_gate as _install_gate
    from agentscore_gate.flask import capture_wallet as _capture

    app = Flask(__name__)
    app.config["TESTING"] = True
    _install_gate(app, api_key="test-key")

    @app.route("/purchase", methods=["POST"])
    def purchase():
        _capture("0xsigner", "evm", idempotency_key="pi_abc")
        return {"ok": True}

    return app


class TestFlaskCaptureWallet:
    def test_captures_when_operator_token_present(self) -> None:
        app = _make_capture_app()
        with patch("agentscore_gate.flask.GateClient.check", return_value=_mock_result()), \
             patch("agentscore_gate.flask.GateClient.capture_wallet") as mock_capture:
            client = app.test_client()
            resp = client.post("/purchase", headers={"x-operator-token": "opc_abc"})
            assert resp.status_code == 200
            mock_capture.assert_called_once_with(
                "opc_abc", "0xsigner", "evm", idempotency_key="pi_abc",
            )

    def test_no_ops_when_wallet_authenticated(self) -> None:
        app = _make_capture_app()
        with patch("agentscore_gate.flask.GateClient.check", return_value=_mock_result()), \
             patch("agentscore_gate.flask.GateClient.capture_wallet") as mock_capture:
            client = app.test_client()
            resp = client.post("/purchase", headers={"x-wallet-address": "0xabc"})
            assert resp.status_code == 200
            mock_capture.assert_not_called()

    def test_no_ops_outside_request_context(self) -> None:
        """Calling capture_wallet without a Flask request context must not crash.

        Defensive: users who import capture_wallet into a background worker would otherwise
        see a RuntimeError from Flask's ``g`` proxy.
        """
        from agentscore_gate.flask import capture_wallet

        app = Flask(__name__)  # no gate registered
        # App context but no request context — Flask's `g` is only meaningful inside a request.
        with (
            app.app_context(),
            patch("agentscore_gate.flask.GateClient.capture_wallet") as mock_capture,
        ):
            capture_wallet("0xsigner", "evm")
            mock_capture.assert_not_called()


class TestFlaskUserAgent:
    """Flask adapter user_agent + default User-Agent header coverage."""

    def test_default_user_agent_format(self) -> None:
        import httpx
        import respx

        app = _make_app()

        with respx.mock:
            route = respx.post("https://api.agentscore.sh/v1/assess").mock(
                return_value=httpx.Response(200, json={"decision": "allow", "decision_reasons": []}),
            )
            client = app.test_client()
            client.get("/", headers={"x-wallet-address": "0xabc"})
            assert route.called
            ua = route.calls[0].request.headers["User-Agent"]
            assert ua.startswith("agentscore-gate/")

    def test_custom_user_agent_prepended(self) -> None:
        import httpx
        import respx

        app = _make_app(user_agent="myapp/2.0")

        with respx.mock:
            route = respx.post("https://api.agentscore.sh/v1/assess").mock(
                return_value=httpx.Response(200, json={"decision": "allow", "decision_reasons": []}),
            )
            client = app.test_client()
            client.get("/", headers={"x-wallet-address": "0xabc"})
            ua = route.calls[0].request.headers["User-Agent"]
            assert ua.startswith("myapp/2.0 (agentscore-gate/")


class TestFlaskChainOption:
    """Flask adapter chain= constructor option forwarding."""

    def test_constructor_chain_stored_and_forwarded(self) -> None:
        import json

        import httpx
        import respx

        app = _make_app(chain="solana")

        with respx.mock:
            route = respx.post("https://api.agentscore.sh/v1/assess").mock(
                return_value=httpx.Response(200, json={"decision": "allow", "decision_reasons": []}),
            )
            client = app.test_client()
            client.get("/", headers={"x-wallet-address": "0xabc"})
            body = json.loads(route.calls[0].request.content)
            assert body["chain"] == "solana"
