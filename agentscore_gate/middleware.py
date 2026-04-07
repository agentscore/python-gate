"""ASGI middleware for trust-gating requests using AgentScore."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from agentscore_gate.client import GateClient, PaymentRequiredError
from agentscore_gate.types import DenialReason, Grade

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from starlette.types import ASGIApp, Receive, Scope, Send

DEFAULT_ADDRESS_HEADER = "x-wallet-address"


def _default_extract_address(request: Request) -> str | None:
    value = request.headers.get(DEFAULT_ADDRESS_HEADER)
    if value and len(value) > 0:
        return value
    return None


async def _default_on_denied(_request: Request, reason: DenialReason) -> JSONResponse:
    body: dict[str, Any] = {"error": reason.code}
    if reason.decision is not None:
        body["decision"] = reason.decision
    if reason.reasons:
        body["reasons"] = reason.reasons
    if reason.verify_url:
        body["verify_url"] = reason.verify_url
    return JSONResponse(body, status_code=403)


class AgentScoreGate:
    """ASGI middleware that gates requests based on AgentScore wallet reputation.

    Usage with Starlette / FastAPI::

        app.add_middleware(
            AgentScoreGate,
            api_key="ask_...",
            min_score=50,
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        api_key: str,
        min_grade: Grade | None = None,
        min_score: int | None = None,
        require_verified_activity: bool | None = None,
        require_kyc: bool | None = None,
        require_sanctions_clear: bool | None = None,
        min_age: int | None = None,
        blocked_jurisdictions: list[str] | None = None,
        require_entity_type: str | None = None,
        fail_open: bool = False,
        cache_seconds: int = 300,
        base_url: str = "https://api.agentscore.sh",
        chain: str | None = None,
        extract_address: Callable[[Request], str | None] | None = None,
        on_denied: Callable[[Request, DenialReason], Awaitable[JSONResponse]] | None = None,
    ) -> None:
        self.app = app
        self._client = GateClient(
            api_key=api_key,
            min_grade=min_grade,
            min_score=min_score,
            require_verified_activity=require_verified_activity,
            require_kyc=require_kyc,
            require_sanctions_clear=require_sanctions_clear,
            min_age=min_age,
            blocked_jurisdictions=blocked_jurisdictions,
            require_entity_type=require_entity_type,
            fail_open=fail_open,
            cache_seconds=cache_seconds,
            base_url=base_url,
            chain=chain,
        )
        self._extract_address = extract_address or _default_extract_address
        self._on_denied = on_denied or _default_on_denied

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive, send)

        address = self._extract_address(request)
        if not address:
            if self._client.fail_open:
                await self.app(scope, receive, send)
                return
            reason = DenialReason(code="missing_wallet_address")
            response = await self._on_denied(request, reason)
            await response(scope, receive, send)
            return

        try:
            result = await self._client.acheck(address)

            if result.allow:
                scope["state"] = {**scope.get("state", {}), "agentscore": result.raw}
                await self.app(scope, receive, send)
                return

            reason = DenialReason(
                code="wallet_not_trusted",
                decision=result.decision,
                reasons=result.reasons,
                verify_url=result.verify_url,
            )
            response = await self._on_denied(request, reason)
            await response(scope, receive, send)
        except PaymentRequiredError:
            if self._client.fail_open:
                await self.app(scope, receive, send)
                return
            reason = DenialReason(code="payment_required")
            response = await self._on_denied(request, reason)
            await response(scope, receive, send)
        except Exception:
            if self._client.fail_open:
                await self.app(scope, receive, send)
                return
            reason = DenialReason(code="api_error")
            response = await self._on_denied(request, reason)
            await response(scope, receive, send)
