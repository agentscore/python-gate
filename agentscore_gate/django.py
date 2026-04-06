"""Django middleware for trust-gating requests using AgentScore."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest, JsonResponse

from agentscore_gate.client import GateClient, PaymentRequiredError
from agentscore_gate.types import DenialReason

DEFAULT_ADDRESS_HEADER = "HTTP_X_WALLET_ADDRESS"


class AgentScoreMiddleware:
    """Django middleware that gates requests based on AgentScore wallet reputation.

    Usage in settings.py::

        MIDDLEWARE = [
            ...
            "agentscore_gate.django.AgentScoreMiddleware",
            ...
        ]

        AGENTSCORE_GATE = {
            "api_key": "ask_...",
            "min_score": 50,
        }
    """

    def __init__(self, get_response: Any) -> None:
        from django.conf import settings

        config: dict[str, Any] = getattr(settings, "AGENTSCORE_GATE", {})

        self._client = GateClient(
            api_key=config.get("api_key", ""),
            min_grade=config.get("min_grade"),
            min_score=config.get("min_score"),
            require_verified_activity=config.get("require_verified_activity"),
            require_kyc=config.get("require_kyc"),
            require_sanctions_clear=config.get("require_sanctions_clear"),
            min_age=config.get("min_age"),
            blocked_jurisdictions=config.get("blocked_jurisdictions"),
            require_entity_type=config.get("require_entity_type"),
            fail_open=config.get("fail_open", False),
            cache_seconds=config.get("cache_seconds", 300),
            base_url=config.get("base_url", "https://api.agentscore.sh"),
        )
        self._extract_address = config.get("extract_address", self._default_extract_address)
        self._extract_chain = config.get("extract_chain", self._default_extract_chain)
        self._on_denied = config.get("on_denied", self._default_on_denied)
        self.get_response = get_response

    @staticmethod
    def _default_extract_address(request: HttpRequest) -> str | None:
        value = request.META.get(DEFAULT_ADDRESS_HEADER)
        if value and len(value) > 0:
            return value
        return None

    @staticmethod
    def _default_extract_chain(_request: HttpRequest) -> str | None:
        return None

    @staticmethod
    def _default_on_denied(_request: HttpRequest, reason: DenialReason) -> JsonResponse:
        body: dict[str, Any] = {"error": reason.code}
        if reason.decision is not None:
            body["decision"] = reason.decision
        if reason.reasons:
            body["reasons"] = reason.reasons
        return JsonResponse(body, status=403)

    def __call__(self, request: HttpRequest) -> Any:
        """Process the request."""
        address = self._extract_address(request)

        if not address:
            if self._client.fail_open:
                return self.get_response(request)
            return self._on_denied(request, DenialReason(code="missing_wallet_address"))

        chain = self._extract_chain(request) or "base"

        try:
            result = self._client.check(address, chain)

            if result.allow:
                request.agentscore = result.raw  # type: ignore[attr-defined]
                return self.get_response(request)

            reason = DenialReason(code="wallet_not_trusted", decision=result.decision, reasons=result.reasons)
            return self._on_denied(request, reason)
        except PaymentRequiredError:
            if self._client.fail_open:
                return self.get_response(request)
            return self._on_denied(request, DenialReason(code="payment_required"))
        except Exception:
            if self._client.fail_open:
                return self.get_response(request)
            return self._on_denied(request, DenialReason(code="api_error"))
