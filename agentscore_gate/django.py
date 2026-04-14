"""Django middleware for trust-gating requests using AgentScore."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest, JsonResponse

from agentscore_gate.client import GateClient, PaymentRequiredError
from agentscore_gate.types import AgentIdentity, DenialReason

DEFAULT_ADDRESS_HEADER = "HTTP_X_WALLET_ADDRESS"
DEFAULT_TOKEN_HEADER = "HTTP_X_OPERATOR_TOKEN"


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
            "require_kyc": True,
        }
    """

    def __init__(self, get_response: Any) -> None:
        from django.conf import settings

        config: dict[str, Any] = getattr(settings, "AGENTSCORE_GATE", {})

        self._client = GateClient(
            api_key=config.get("api_key", ""),
            require_kyc=config.get("require_kyc"),
            require_sanctions_clear=config.get("require_sanctions_clear"),
            min_age=config.get("min_age"),
            blocked_jurisdictions=config.get("blocked_jurisdictions"),
            allowed_jurisdictions=config.get("allowed_jurisdictions"),
            require_entity_type=config.get("require_entity_type"),
            fail_open=config.get("fail_open", False),
            cache_seconds=config.get("cache_seconds", 300),
            base_url=config.get("base_url", "https://api.agentscore.sh"),
        )
        self._extract_identity = config.get("extract_identity", self._default_extract_identity)
        self._extract_chain = config.get("extract_chain", self._default_extract_chain)
        self._on_denied = config.get("on_denied", self._default_on_denied)
        self.get_response = get_response

    @staticmethod
    def _default_extract_identity(request: HttpRequest) -> AgentIdentity | None:
        token = request.META.get(DEFAULT_TOKEN_HEADER)
        addr = request.META.get(DEFAULT_ADDRESS_HEADER)
        identity = AgentIdentity()
        if token and len(token) > 0:
            identity.operator_token = token
        if addr and len(addr) > 0:
            identity.address = addr
        if identity.operator_token or identity.address:
            return identity
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
        if reason.verify_url:
            body["verify_url"] = reason.verify_url
        return JsonResponse(body, status=403)

    def __call__(self, request: HttpRequest) -> Any:
        """Process the request."""
        identity = self._extract_identity(request)

        if not identity:
            if self._client.fail_open:
                return self.get_response(request)
            return self._on_denied(request, DenialReason(code="missing_identity"))

        chain = self._extract_chain(request) or "base"

        try:
            result = self._client.check_identity(identity, chain)

            if result.allow:
                request.agentscore = result.raw  # type: ignore[attr-defined]
                return self.get_response(request)

            reason = DenialReason(
                code="wallet_not_trusted",
                decision=result.decision,
                reasons=result.reasons,
                verify_url=result.verify_url,
            )
            return self._on_denied(request, reason)
        except PaymentRequiredError:
            if self._client.fail_open:
                return self.get_response(request)
            return self._on_denied(request, DenialReason(code="payment_required"))
        except Exception:
            if self._client.fail_open:
                return self.get_response(request)
            return self._on_denied(request, DenialReason(code="api_error"))
