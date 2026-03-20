"""Flask integration for trust-gating requests using AgentScore."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentscore_gate.client import GateClient, PaymentRequiredError
from agentscore_gate.types import DenialReason, Grade

if TYPE_CHECKING:
    from collections.abc import Callable

    from flask import Flask, Request, Response

DEFAULT_ADDRESS_HEADER = "x-wallet-address"


def _default_extract_address(request: Request) -> str | None:
    value = request.headers.get(DEFAULT_ADDRESS_HEADER)
    if value and len(value) > 0:
        return value
    return None


def _default_extract_chain(_request: Request) -> str | None:
    return None


def _default_on_denied(_request: Request, reason: DenialReason) -> tuple[dict[str, Any], int]:
    body: dict[str, Any] = {"error": reason.code}
    if reason.decision is not None:
        body["decision"] = reason.decision
    if reason.reasons:
        body["reasons"] = reason.reasons
    return body, 403


def agentscore_gate(
    app: Flask,
    *,
    api_key: str,
    min_grade: Grade | None = None,
    min_score: int | None = None,
    require_verified_activity: bool | None = None,
    fail_open: bool = False,
    cache_seconds: int = 300,
    base_url: str = "https://api.agentscore.sh",
    extract_address: Callable[..., str | None] | None = None,
    extract_chain: Callable[..., str | None] | None = None,
    on_denied: Callable[..., Any] | None = None,
) -> None:
    """Register AgentScore gate as a Flask before_request handler.

    Usage::

        from flask import Flask
        from agentscore_gate.flask import agentscore_gate

        app = Flask(__name__)
        agentscore_gate(app, api_key="ask_...", min_score=50)
    """
    from flask import g, jsonify
    from flask import request as flask_request

    client = GateClient(
        api_key=api_key,
        min_grade=min_grade,
        min_score=min_score,
        require_verified_activity=require_verified_activity,
        fail_open=fail_open,
        cache_seconds=cache_seconds,
        base_url=base_url,
    )
    _extract_address = extract_address or _default_extract_address
    _extract_chain = extract_chain or _default_extract_chain
    _on_denied = on_denied or _default_on_denied

    @app.before_request
    def _agentscore_check() -> Response | None:
        address = _extract_address(flask_request)
        if not address:
            if client.fail_open:
                return None
            body, status = _on_denied(flask_request, DenialReason(code="missing_wallet_address"))
            return jsonify(body), status

        chain = _extract_chain(flask_request) or "base"

        try:
            result = client.check(address, chain)

            if result.allow:
                g.agentscore = result.raw
                return None

            reason = DenialReason(code="wallet_not_trusted", decision=result.decision, reasons=result.reasons)
            body, status = _on_denied(flask_request, reason)
            return jsonify(body), status
        except PaymentRequiredError:
            if client.fail_open:
                return None
            body, status = _on_denied(flask_request, DenialReason(code="payment_required"))
            return jsonify(body), status
        except Exception:
            if client.fail_open:
                return None
            body, status = _on_denied(flask_request, DenialReason(code="api_error"))
            return jsonify(body), status
