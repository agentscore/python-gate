"""Tests for the Django integration."""

from __future__ import annotations

import json
from unittest.mock import patch

import django
from django.conf import settings

# Configure Django before importing anything else.
if not settings.configured:
    settings.configure(
        AGENTSCORE_GATE={"api_key": "test-key"},
        MIDDLEWARE=[],
        ROOT_URLCONF="tests.test_django",
        SECRET_KEY="test-secret",  # noqa: S106
    )
    django.setup()

from django.http import HttpRequest, JsonResponse
from django.test import RequestFactory

from agentscore_gate.django import AgentScoreMiddleware
from agentscore_gate.types import AssessResult

# Minimal URL conf for Django test runner.
urlpatterns: list = []


def _ok_response(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True, "agentscore": getattr(request, "agentscore", None)})


def _mock_result(allow: bool = True, decision: str | None = "allow") -> AssessResult:
    return AssessResult(allow=allow, decision=decision, reasons=[], raw={"score": 80, "grade": "B"})


class TestDjangoMiddleware:
    """Django middleware tests."""

    factory = RequestFactory()

    def _make_middleware(self, **config_overrides: object) -> AgentScoreMiddleware:
        original = settings.AGENTSCORE_GATE.copy()
        settings.AGENTSCORE_GATE = {**original, **config_overrides}
        try:
            return AgentScoreMiddleware(_ok_response)
        finally:
            settings.AGENTSCORE_GATE = original

    def test_allows_trusted_wallet(self) -> None:
        mw = self._make_middleware()
        request = self.factory.get("/", HTTP_X_WALLET_ADDRESS="0xabc")
        with patch("agentscore_gate.django.GateClient.check", return_value=_mock_result()):
            resp = mw(request)
            assert resp.status_code == 200
            data = json.loads(resp.content)
            assert data["ok"] is True

    def test_blocks_untrusted_wallet(self) -> None:
        mw = self._make_middleware()
        result = AssessResult(allow=False, decision="deny", reasons=["score_too_low"], raw={})
        request = self.factory.get("/", HTTP_X_WALLET_ADDRESS="0xabc")
        with patch("agentscore_gate.django.GateClient.check", return_value=result):
            resp = mw(request)
            assert resp.status_code == 403
            data = json.loads(resp.content)
            assert data["error"] == "wallet_not_trusted"

    def test_missing_wallet_returns_403(self) -> None:
        mw = self._make_middleware()
        request = self.factory.get("/")
        resp = mw(request)
        assert resp.status_code == 403
        data = json.loads(resp.content)
        assert data["error"] == "missing_wallet_address"

    def test_missing_wallet_fail_open(self) -> None:
        mw = self._make_middleware(fail_open=True)
        request = self.factory.get("/")
        resp = mw(request)
        assert resp.status_code == 200

    def test_api_error_fail_open(self) -> None:
        mw = self._make_middleware(fail_open=True)
        request = self.factory.get("/", HTTP_X_WALLET_ADDRESS="0xabc")
        with patch("agentscore_gate.django.GateClient.check", side_effect=RuntimeError("timeout")):
            resp = mw(request)
            assert resp.status_code == 200

    def test_api_error_fail_closed(self) -> None:
        mw = self._make_middleware()
        request = self.factory.get("/", HTTP_X_WALLET_ADDRESS="0xabc")
        with patch("agentscore_gate.django.GateClient.check", side_effect=RuntimeError("timeout")):
            resp = mw(request)
            assert resp.status_code == 403
            data = json.loads(resp.content)
            assert data["error"] == "api_error"

    def test_attaches_data_to_request(self) -> None:
        mw = self._make_middleware()
        request = self.factory.get("/", HTTP_X_WALLET_ADDRESS="0xabc")
        with patch("agentscore_gate.django.GateClient.check", return_value=_mock_result()):
            mw(request)
            assert hasattr(request, "agentscore")
            assert request.agentscore["score"] == 80  # type: ignore[attr-defined]
