"""Shared session-creation helper used by framework adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from agentscore_gate.types import DenialReason


@dataclass
class CreateSessionOnMissing:
    """Config for auto-creating verification sessions on missing identity.

    When supplied to any framework adapter, missing-identity requests trigger a
    ``POST /v1/sessions`` call and receive a 403 with verify_url + poll instructions
    instead of a bare ``missing_identity`` denial.
    """

    api_key: str
    base_url: str = "https://api.agentscore.sh"
    context: str | None = None
    product_name: str | None = None


def _session_body(cfg: CreateSessionOnMissing) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if cfg.context is not None:
        body["context"] = cfg.context
    if cfg.product_name is not None:
        body["product_name"] = cfg.product_name
    return body


def _session_headers(cfg: CreateSessionOnMissing, user_agent: str) -> dict[str, str]:
    return {
        "X-API-Key": cfg.api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": user_agent,
    }


def _session_url(cfg: CreateSessionOnMissing) -> str:
    return f"{cfg.base_url.rstrip('/')}/v1/sessions"


def _session_denial_reason(data: dict[str, Any]) -> DenialReason:
    return DenialReason(
        code="identity_verification_required",
        verify_url=data.get("verify_url"),
        session_id=data.get("session_id"),
        poll_secret=data.get("poll_secret"),
        agent_instructions=data.get("agent_instructions"),
    )


async def try_create_session_denial_reason(
    cfg: CreateSessionOnMissing,
    user_agent: str,
) -> DenialReason | None:
    """Hit ``POST /v1/sessions`` and return a populated DenialReason, or None on failure.

    Silent: all errors swallowed to match the original inline middleware behavior.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                _session_url(cfg),
                headers=_session_headers(cfg, user_agent),
                json=_session_body(cfg),
            )
        if not resp.is_success:
            return None
        return _session_denial_reason(resp.json())
    except Exception:
        return None


def try_create_session_denial_reason_sync(
    cfg: CreateSessionOnMissing,
    user_agent: str,
) -> DenialReason | None:
    """Synchronous variant of :func:`try_create_session_denial_reason` for Flask/Django."""
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                _session_url(cfg),
                headers=_session_headers(cfg, user_agent),
                json=_session_body(cfg),
            )
        if not resp.is_success:
            return None
        return _session_denial_reason(resp.json())
    except Exception:
        return None
