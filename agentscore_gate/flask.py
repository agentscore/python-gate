"""Flask integration for trust-gating requests using AgentScore."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentscore_gate.client import GateClient, PaymentRequiredError
from agentscore_gate.types import AgentIdentity, DenialReason

if TYPE_CHECKING:
    from collections.abc import Callable

    from flask import Flask, Request, Response

DEFAULT_ADDRESS_HEADER = "x-wallet-address"
DEFAULT_TOKEN_HEADER = "x-operator-token"


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
    return body, 403


def agentscore_gate(
    app: Flask,
    *,
    api_key: str,
    require_kyc: bool | None = None,
    require_sanctions_clear: bool | None = None,
    min_age: int | None = None,
    blocked_jurisdictions: list[str] | None = None,
    allowed_jurisdictions: list[str] | None = None,
    require_entity_type: str | None = None,
    fail_open: bool = False,
    cache_seconds: int = 300,
    base_url: str = "https://api.agentscore.sh",
    extract_identity: Callable[[Request], AgentIdentity | None] | None = None,
    extract_chain: Callable[[Request], str | None] | None = None,
    on_denied: Callable[[Request, DenialReason], tuple[dict[str, Any], int]] | None = None,
) -> None:
    """Register AgentScore gate as a Flask before_request handler.

    Usage::

        from flask import Flask
        from agentscore_gate.flask import agentscore_gate

        app = Flask(__name__)
        agentscore_gate(app, api_key="ask_...", require_kyc=True)
    """
    from flask import g, jsonify
    from flask import request as flask_request

    client = GateClient(
        api_key=api_key,
        require_kyc=require_kyc,
        require_sanctions_clear=require_sanctions_clear,
        min_age=min_age,
        blocked_jurisdictions=blocked_jurisdictions,
        allowed_jurisdictions=allowed_jurisdictions,
        require_entity_type=require_entity_type,
        fail_open=fail_open,
        cache_seconds=cache_seconds,
        base_url=base_url,
    )
    _resolve_identity = extract_identity or _default_extract_identity
    _extract_chain = extract_chain or _default_extract_chain
    _on_denied = on_denied or _default_on_denied

    @app.before_request
    def _agentscore_check() -> Response | None:
        identity = _resolve_identity(flask_request)
        if not identity:
            if client.fail_open:
                return None
            try:
                body, status = _on_denied(flask_request, DenialReason(code="missing_identity"))
            except (TypeError, ValueError) as exc:
                msg = "on_denied must return a (dict, int) tuple, e.g. ({'error': 'denied'}, 403)"
                raise TypeError(msg) from exc
            return jsonify(body), status

        chain = _extract_chain(flask_request) or "base"

        try:
            result = client.check_identity(identity, chain)

            if result.allow:
                g.agentscore = result.raw
                return None

            reason = DenialReason(
                code="wallet_not_trusted",
                decision=result.decision,
                reasons=result.reasons,
                verify_url=result.verify_url,
            )
            try:
                body, status = _on_denied(flask_request, reason)
            except (TypeError, ValueError) as exc:
                msg = "on_denied must return a (dict, int) tuple, e.g. ({'error': 'denied'}, 403)"
                raise TypeError(msg) from exc
            return jsonify(body), status
        except PaymentRequiredError:
            if client.fail_open:
                return None
            try:
                body, status = _on_denied(flask_request, DenialReason(code="payment_required"))
            except (TypeError, ValueError) as exc:
                msg = "on_denied must return a (dict, int) tuple, e.g. ({'error': 'denied'}, 403)"
                raise TypeError(msg) from exc
            return jsonify(body), status
        except TypeError:
            raise
        except Exception:
            if client.fail_open:
                return None
            try:
                body, status = _on_denied(flask_request, DenialReason(code="api_error"))
            except (TypeError, ValueError) as exc:
                msg = "on_denied must return a (dict, int) tuple, e.g. ({'error': 'denied'}, 403)"
                raise TypeError(msg) from exc
            return jsonify(body), status
