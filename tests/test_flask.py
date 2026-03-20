"""Tests for the Flask integration."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from flask import Flask

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

    def test_requires_api_key(self) -> None:
        with pytest.raises(ValueError, match="API key is required"):
            app = Flask(__name__)
            agentscore_gate(app, api_key="")
