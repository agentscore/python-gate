"""Shared serialization for DenialReason → HTTP body dict.

Every adapter (ASGI, FastAPI, Flask, Django, AIOHTTP, Sanic) renders the same
body shape for a denial — this helper keeps them in sync and in one place.
Includes the wallet-signer-match fields and the agent_memory payload.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from agentscore_gate.types import DenialReason, build_agent_memory_hint

_MISSING_IDENTITY_INSTRUCTIONS = json.dumps(
    {
        "action": "probe_identity_then_session",
        "steps": [
            (
                "If you have a wallet in hand AND this merchant accepts a wallet-signing rail "
                "(Tempo MPP or x402 — see openapi.json x-payment-info): send X-Wallet-Address "
                "and retry. If the wallet is linked to an AgentScore operator anywhere (via "
                "prior SIWE claim or prior captureWallet), this passes in one round trip."
            ),
            (
                "If step 1 is denied (wallet_signer_mismatch, unknown_address, or missing_kyc) "
                "OR you already have a stored operator_token: send X-Operator-Token: opc_... "
                "and retry."
            ),
            (
                "If neither works: retry with NO identity header. The 403 will include "
                "verify_url + session_id + poll_secret. Share verify_url with the user, then "
                "poll poll_url every 5s with X-Poll-Secret until status=verified — the poll "
                "response returns a one-time operator_token."
            ),
        ],
        "user_message": (
            "Try X-Wallet-Address first if you have a wallet and the merchant accepts Tempo/x402; "
            "fall back to a stored X-Operator-Token, then to the session/verify flow described in "
            "agent_memory.bootstrap."
        ),
    }
)

WALLET_SIGNER_MISMATCH_INSTRUCTIONS = json.dumps(
    {
        "action": "resign_or_switch_to_operator_token",
        "steps": [
            (
                "Preferred: re-submit the payment signed by expected_signer (or any entry in "
                "linked_wallets — same-operator wallets are fungible) and retry with the same "
                "X-Wallet-Address."
            ),
            (
                "Alternative: drop X-Wallet-Address and retry with X-Operator-Token. Use a "
                "stored opc_... if you have one; otherwise call POST /v1/credentials or run "
                "the session/verify flow to mint one."
            ),
        ],
        "user_message": (
            "The payment signer resolves to a different operator than X-Wallet-Address. Re-sign "
            "from expected_signer or any linked_wallets entry, or switch to X-Operator-Token."
        ),
    }
)

WALLET_AUTH_REQUIRES_WALLET_SIGNING_INSTRUCTIONS = json.dumps(
    {
        "action": "switch_to_operator_token",
        "steps": [
            (
                "This payment rail (Stripe SPT, card) carries no wallet signature — "
                "X-Wallet-Address cannot be verified against the payment."
            ),
            (
                "Drop X-Wallet-Address and retry with X-Operator-Token. If you do not have a "
                "stored opc_..., retry with no identity header to receive a verification session."
            ),
        ],
        "user_message": (
            "Wallet-address identity is only supported on wallet-signing rails (Tempo MPP, x402). "
            "On Stripe or card, use X-Operator-Token instead."
        ),
    }
)


def build_missing_identity_reason(base_url: str = "https://api.agentscore.sh") -> DenialReason:
    """Construct a missing_identity DenialReason with the cross-merchant memory hint attached.

    Emitted when the adapter has no identity AND no create_session_on_missing config — this is the
    cold-start bootstrap path where the memory hint is most useful. The attached agent_instructions
    hint the agent to try stored identity (returning-customer fast path) before running the
    session/verify flow.
    """
    return DenialReason(
        code="missing_identity",
        agent_instructions=_MISSING_IDENTITY_INSTRUCTIONS,
        agent_memory=build_agent_memory_hint(base_url),
    )


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
