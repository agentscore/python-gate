"""ASGI middleware for trust-gating requests using AgentScore."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse

from agentscore_gate.client import GateClient, PaymentRequiredError
from agentscore_gate.types import AgentIdentity, DenialReason

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from starlette.types import ASGIApp, Receive, Scope, Send

DEFAULT_ADDRESS_HEADER = "x-wallet-address"
DEFAULT_TOKEN_HEADER = "x-operator-token"


@dataclass
class CreateSessionOnMissing:
    """Config for auto-creating verification sessions on missing identity."""

    api_key: str
    base_url: str = "https://api.agentscore.sh"
    context: str | None = None
    product_name: str | None = None


def _default_extract_identity(request: Request) -> AgentIdentity | None:
    token = request.headers.get(DEFAULT_TOKEN_HEADER)
    addr = request.headers.get(DEFAULT_ADDRESS_HEADER)
    identity = AgentIdentity()
    if token and len(token) > 0:
        identity.operator_token = token
    if addr and len(addr) > 0:
        identity.address = addr
    if identity.operator_token or identity.address:
        return identity
    return None


async def _default_on_denied(_request: Request, reason: DenialReason) -> JSONResponse:
    body: dict[str, Any] = {"error": reason.code}
    if reason.decision is not None:
        body["decision"] = reason.decision
    if reason.reasons:
        body["reasons"] = reason.reasons
    if reason.verify_url:
        body["verify_url"] = reason.verify_url
    if reason.session_id:
        body["session_id"] = reason.session_id
    if reason.poll_secret:
        body["poll_secret"] = reason.poll_secret
    if reason.agent_instructions:
        body["agent_instructions"] = reason.agent_instructions
    return JSONResponse(body, status_code=403)


class AgentScoreGate:
    """ASGI middleware that gates requests based on AgentScore wallet reputation.

    Usage with Starlette / FastAPI::

        app.add_middleware(
            AgentScoreGate,
            api_key="ask_...",
            require_kyc=True,
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        api_key: str,
        require_kyc: bool | None = None,
        require_sanctions_clear: bool | None = None,
        min_age: int | None = None,
        blocked_jurisdictions: list[str] | None = None,
        allowed_jurisdictions: list[str] | None = None,
        fail_open: bool = False,
        cache_seconds: int = 300,
        base_url: str = "https://api.agentscore.sh",
        chain: str | None = None,
        extract_identity: Callable[[Request], AgentIdentity | None] | None = None,
        on_denied: Callable[[Request, DenialReason], Awaitable[JSONResponse]] | None = None,
        create_session_on_missing: CreateSessionOnMissing | None = None,
    ) -> None:
        self.app = app
        self._client = GateClient(
            api_key=api_key,
            require_kyc=require_kyc,
            require_sanctions_clear=require_sanctions_clear,
            min_age=min_age,
            blocked_jurisdictions=blocked_jurisdictions,
            allowed_jurisdictions=allowed_jurisdictions,
            fail_open=fail_open,
            cache_seconds=cache_seconds,
            base_url=base_url,
            chain=chain,
        )
        self._extract_identity = extract_identity or _default_extract_identity
        self._on_denied = on_denied or _default_on_denied
        self._create_session_on_missing = create_session_on_missing

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive, send)

        identity = self._extract_identity(request)
        if not identity:
            if self._client.fail_open:
                await self.app(scope, receive, send)
                return

            if self._create_session_on_missing:
                try:
                    session_base = self._create_session_on_missing.base_url.rstrip("/")
                    session_body: dict[str, Any] = {}
                    cfg = self._create_session_on_missing
                    if cfg.context is not None:
                        session_body["context"] = cfg.context
                    if cfg.product_name is not None:
                        session_body["product_name"] = cfg.product_name
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.post(
                            f"{session_base}/v1/sessions",
                            headers={
                                "X-API-Key": cfg.api_key,
                                "Content-Type": "application/json",
                                "Accept": "application/json",
                            },
                            json=session_body,
                        )
                    if resp.is_success:
                        data = resp.json()
                        reason = DenialReason(
                            code="identity_verification_required",
                            verify_url=data.get("verify_url"),
                            session_id=data.get("session_id"),
                            poll_secret=data.get("poll_secret"),
                            agent_instructions=data.get("agent_instructions"),
                        )
                        response = await self._on_denied(request, reason)
                        await response(scope, receive, send)
                        return
                except Exception:  # noqa: S110
                    pass

            reason = DenialReason(code="missing_identity")
            response = await self._on_denied(request, reason)
            await response(scope, receive, send)
            return

        try:
            result = await self._client.acheck_identity(identity)

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
