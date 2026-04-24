"""Shared serialization for DenialReason → HTTP body dict.

Every adapter (ASGI, FastAPI, Flask, Django, AIOHTTP, Sanic) renders the same
body shape for a denial — this helper keeps them in sync and in one place.
Includes the wallet-signer-match fields and the agent_memory payload.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from agentscore_gate.types import DenialReason, build_agent_memory_hint


def build_missing_identity_reason(base_url: str = "https://api.agentscore.sh") -> DenialReason:
    """Construct a missing_identity DenialReason with the cross-merchant memory hint attached.

    Emitted when the adapter has no identity AND no create_session_on_missing config — this is the
    cold-start bootstrap path where the memory hint is most useful.
    """
    return DenialReason(code="missing_identity", agent_memory=build_agent_memory_hint(base_url))


def denial_reason_to_body(reason: DenialReason) -> dict[str, Any]:
    """Marshal a DenialReason dataclass into a flat dict suitable for the 403 JSON body.

    Shared across all adapters. Omits falsy optional fields so the body stays compact.
    Always includes ``error`` set from ``reason.code``.
    """
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
    # Cross-merchant pattern hint.
    if reason.agent_memory is not None:
        body["agent_memory"] = asdict(reason.agent_memory)
    # Wallet-signer-match fields, populated only for wallet_signer_mismatch.
    if reason.claimed_operator:
        body["claimed_operator"] = reason.claimed_operator
    if reason.actual_signer_operator is not None:
        body["actual_signer_operator"] = reason.actual_signer_operator
    if reason.expected_signer:
        body["expected_signer"] = reason.expected_signer
    if reason.actual_signer:
        body["actual_signer"] = reason.actual_signer
    if reason.linked_wallets:
        body["linked_wallets"] = reason.linked_wallets
    # Merchant-supplied fields from on_before_session hook.
    if reason.extra:
        body.update(reason.extra)
    return body
