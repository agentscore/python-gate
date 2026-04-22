"""Sanic integration for trust-gating requests using AgentScore."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentscore_gate.client import GateClient, PaymentRequiredError
from agentscore_gate.sessions import CreateSessionOnMissing, try_create_session_denial_reason
from agentscore_gate.types import AgentIdentity, DenialReason, Network

if TYPE_CHECKING:
    from collections.abc import Callable

    from sanic import HTTPResponse, Request, Sanic

DEFAULT_ADDRESS_HEADER = "x-wallet-address"
DEFAULT_TOKEN_HEADER = "x-operator-token"
GATE_STATE_ATTR = "_agentscore_gate"

__all__ = [
    "CreateSessionOnMissing",
    "agentscore_gate",
    "capture_wallet",
]


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


def _default_extract_chain(_request: Request) -> str | None:
    return None


def _default_on_denied(_request: Request, reason: DenialReason) -> tuple[dict[str, Any], int]:
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
    if reason.poll_url:
        body["poll_url"] = reason.poll_url
    if reason.agent_instructions:
        body["agent_instructions"] = reason.agent_instructions
    if reason.extra:
        body.update(reason.extra)
    return body, 403


def agentscore_gate(
    app: Sanic,
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
    user_agent: str | None = None,
    extract_identity: Callable[[Request], AgentIdentity | None] | None = None,
    extract_chain: Callable[[Request], str | None] | None = None,
    on_denied: Callable[[Request, DenialReason], tuple[dict[str, Any], int]] | None = None,
    create_session_on_missing: CreateSessionOnMissing | None = None,
) -> None:
    """Register AgentScore gate as a Sanic request middleware.

    Usage::

        from sanic import Sanic
        from agentscore_gate.sanic import agentscore_gate

        app = Sanic("myapp")
        agentscore_gate(app, api_key="ask_...", require_kyc=True)
    """
    from sanic import response

    client = GateClient(
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
        user_agent=user_agent,
    )
    _resolve_identity = extract_identity or _default_extract_identity
    _extract_chain = extract_chain or _default_extract_chain
    _on_denied = on_denied or _default_on_denied

    @app.middleware("request")
    async def _agentscore_check(request: Request) -> HTTPResponse | None:
        identity = _resolve_identity(request)
        # Stash state on request.ctx so capture_wallet() can look up operator_token + client
        # after the handler runs.
        setattr(
            request.ctx,
            GATE_STATE_ATTR,
            {"client": client, "operator_token": identity.operator_token if identity else None},
        )

        if not identity:
            if client.fail_open:
                return None
            if create_session_on_missing is not None:
                session_reason = await try_create_session_denial_reason(
                    create_session_on_missing,
                    client.user_agent,
                    request,
                )
                if session_reason is not None:
                    body, status = _on_denied(request, session_reason)
                    return response.json(body, status=status)
            body, status = _on_denied(request, DenialReason(code="missing_identity"))
            return response.json(body, status=status)

        chain_override = _extract_chain(request)

        try:
            result = await client.acheck_identity(identity, chain_override)

            if result.allow:
                request.ctx.agentscore = result.raw
                return None

            reason = DenialReason(
                code="wallet_not_trusted",
                decision=result.decision,
                reasons=result.reasons,
                verify_url=result.verify_url,
            )
            body, status = _on_denied(request, reason)
            return response.json(body, status=status)
        except PaymentRequiredError:
            if client.fail_open:
                return None
            body, status = _on_denied(request, DenialReason(code="payment_required"))
            return response.json(body, status=status)
        except Exception:
            if client.fail_open:
                return None
            body, status = _on_denied(request, DenialReason(code="api_error"))
            return response.json(body, status=status)


async def capture_wallet(
    request: Request,
    wallet_address: str,
    network: Network,
    idempotency_key: str | None = None,
) -> None:
    """Report a wallet that paid under the operator_token the Sanic gate extracted on this request.

    Fire-and-forget: no-ops silently if the gate didn't run, the request was wallet-authenticated
    (no operator_token to associate), or the API call fails.

    Usage::

        @app.post("/purchase")
        async def purchase(request):
            # ... run payment, recover signer wallet from the payload ...
            await capture_wallet(request, signer, "evm", idempotency_key=payment_intent_id)
            return response.json({"ok": True})
    """
    state = getattr(request.ctx, GATE_STATE_ATTR, None)
    if not state or not state.get("operator_token"):
        return
    await state["client"].acapture_wallet(
        state["operator_token"],
        wallet_address,
        network,
        idempotency_key=idempotency_key,
    )
