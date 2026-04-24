"""Tests for TEC-226 signer-match helpers and TEC-227 agent_memory hint."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from agentscore_gate import (
    AgentMemoryHint,
    GateClient,
    VerifyWalletSignerMatchOptions,
    build_agent_memory_hint,
    extract_x402_signer,
)

API_KEY = "test-api-key"
WALLET_A = "0x1111111111111111111111111111111111111111"
WALLET_B = "0x2222222222222222222222222222222222222222"


# ---------------------------------------------------------------------------
# build_agent_memory_hint — TEC-227
# ---------------------------------------------------------------------------


def test_agent_memory_hint_has_core_fields() -> None:
    hint = build_agent_memory_hint("https://api.agentscore.sh")
    assert hint.save_for_future_agentscore_gates is True
    assert "AgentScore" in hint.pattern_summary
    assert hint.identity_check_endpoint == "https://api.agentscore.sh/v1/credentials"
    assert hint.list_wallets_endpoint == "https://api.agentscore.sh/v1/credentials/wallets"
    assert "X-Wallet-Address" in hint.identity_paths["wallet"]
    assert "X-Operator-Token" in hint.identity_paths["operator_token"]
    assert "operator_token" in hint.do_not_persist_in_memory


def test_agent_memory_hint_strips_trailing_slash() -> None:
    hint = build_agent_memory_hint("https://api.agentscore.sh/")
    assert hint.identity_check_endpoint == "https://api.agentscore.sh/v1/credentials"


def test_agent_memory_hint_ignores_merchant_base_url() -> None:
    # Sec1: memory pointers must always be the canonical AgentScore API to prevent
    # malicious merchants from phishing agents via their own baseUrl configuration.
    hint = build_agent_memory_hint("https://evil.example.com")
    assert hint.identity_check_endpoint == "https://api.agentscore.sh/v1/credentials"
    assert hint.list_wallets_endpoint == "https://api.agentscore.sh/v1/credentials/wallets"


def test_agent_memory_hint_is_dataclass() -> None:
    hint = build_agent_memory_hint("https://api.agentscore.sh")
    assert isinstance(hint, AgentMemoryHint)


# ---------------------------------------------------------------------------
# extract_x402_signer
# ---------------------------------------------------------------------------


def _encode_x402(sender: str) -> str:
    body = {"payload": {"authorization": {"from": sender}}}
    return base64.b64encode(json.dumps(body).encode("utf-8")).decode("ascii")


def test_extract_x402_signer_valid() -> None:
    header = _encode_x402(WALLET_A)
    assert extract_x402_signer(header) == WALLET_A.lower()


def test_extract_x402_signer_none_for_missing_header() -> None:
    assert extract_x402_signer(None) is None
    assert extract_x402_signer("") is None


def test_extract_x402_signer_none_for_malformed() -> None:
    assert extract_x402_signer("!!!not-base64!!!") is None
    assert extract_x402_signer(base64.b64encode(b"not json").decode("ascii")) is None


def test_extract_x402_signer_none_for_missing_from() -> None:
    header = base64.b64encode(json.dumps({"payload": {"authorization": {}}}).encode()).decode()
    assert extract_x402_signer(header) is None


def test_extract_x402_signer_rejects_non_evm() -> None:
    header = base64.b64encode(json.dumps({"payload": {"authorization": {"from": "not-a-wallet"}}}).encode()).decode()
    assert extract_x402_signer(header) is None


# ---------------------------------------------------------------------------
# GateClient.verify_wallet_signer_match — TEC-226
# ---------------------------------------------------------------------------


def test_verify_wallet_signer_match_byte_equal_pass() -> None:
    client = GateClient(api_key=API_KEY)
    result = client.verify_wallet_signer_match(
        VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=WALLET_A),
    )
    assert result.kind == "pass"


def test_verify_wallet_signer_match_requires_signing_on_null_signer() -> None:
    client = GateClient(api_key=API_KEY)
    result = client.verify_wallet_signer_match(
        VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=None),
    )
    assert result.kind == "wallet_auth_requires_wallet_signing"
    assert result.claimed_wallet == WALLET_A


def test_verify_wallet_signer_match_same_operator_pass() -> None:
    client = GateClient(api_key=API_KEY)

    def fake_post(*_args: object, **_kwargs: object) -> MagicMock:
        resp = MagicMock()
        resp.is_success = True
        resp.status_code = 200
        resp.json = lambda: {"resolved_operator": "op_shared", "decision": "allow"}
        return resp

    with patch.object(client._sync_client, "post", side_effect=fake_post):
        result = client.verify_wallet_signer_match(
            VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=WALLET_B),
        )
    assert result.kind == "pass"
    assert result.claimed_operator == "op_shared"
    assert result.signer_operator == "op_shared"


def test_verify_wallet_signer_match_different_operator_rejects() -> None:
    client = GateClient(api_key=API_KEY)
    operators = iter(["op_claimed", "op_attacker"])

    def fake_post(*_args: object, **_kwargs: object) -> MagicMock:
        resp = MagicMock()
        resp.is_success = True
        resp.status_code = 200
        op = next(operators)
        resp.json = lambda op=op: {"resolved_operator": op}
        return resp

    with patch.object(client._sync_client, "post", side_effect=fake_post):
        result = client.verify_wallet_signer_match(
            VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=WALLET_B),
        )
    assert result.kind == "wallet_signer_mismatch"
    assert result.claimed_operator == "op_claimed"
    assert result.actual_signer_operator == "op_attacker"
    assert result.expected_signer == WALLET_A.lower()
    assert result.actual_signer == WALLET_B.lower()


def test_verify_wallet_signer_match_transient_error_emits_api_error() -> None:
    """Sec2: transient /v1/assess failures must NOT be conflated with wallet_signer_mismatch."""
    client = GateClient(api_key=API_KEY)

    def fake_post(*_args: object, **_kwargs: object) -> MagicMock:
        resp = MagicMock()
        resp.is_success = False
        resp.status_code = 503
        return resp

    with patch.object(client._sync_client, "post", side_effect=fake_post):
        result = client.verify_wallet_signer_match(
            VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=WALLET_B),
        )
    assert result.kind == "api_error"
    assert result.claimed_wallet == WALLET_A.lower()


@pytest.mark.asyncio
async def test_averify_wallet_signer_match_transient_error_emits_api_error() -> None:
    client = GateClient(api_key=API_KEY)
    from unittest.mock import AsyncMock

    async def fake_apost(*_args: object, **_kwargs: object) -> MagicMock:
        resp = MagicMock()
        resp.is_success = False
        return resp

    client._async_client.post = AsyncMock(side_effect=fake_apost)
    result = await client.averify_wallet_signer_match(
        VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=WALLET_B),
    )
    assert result.kind == "api_error"


def test_verify_wallet_signer_match_unlinked_signer_rejects() -> None:
    client = GateClient(api_key=API_KEY)
    operators = iter(["op_claimed", None])

    def fake_post(*_args: object, **_kwargs: object) -> MagicMock:
        resp = MagicMock()
        resp.is_success = True
        resp.status_code = 200
        op = next(operators)
        resp.json = lambda op=op: {"resolved_operator": op}
        return resp

    with patch.object(client._sync_client, "post", side_effect=fake_post):
        result = client.verify_wallet_signer_match(
            VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=WALLET_B),
        )
    assert result.kind == "wallet_signer_mismatch"
    assert result.actual_signer_operator is None


@pytest.mark.asyncio
async def test_averify_wallet_signer_match_byte_equal_pass() -> None:
    client = GateClient(api_key=API_KEY)
    result = await client.averify_wallet_signer_match(
        VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=WALLET_A),
    )
    assert result.kind == "pass"


@pytest.mark.asyncio
async def test_averify_wallet_signer_match_requires_signing_on_null_signer() -> None:
    client = GateClient(api_key=API_KEY)
    result = await client.averify_wallet_signer_match(
        VerifyWalletSignerMatchOptions(claimed_wallet=WALLET_A, signer=None),
    )
    assert result.kind == "wallet_auth_requires_wallet_signing"


# ---------------------------------------------------------------------------
# Adapter wrapper tests — TEC-226 Section IV: token wins, signer check no-ops
# when BOTH headers are sent. Also tests the new agent_memory body serialization.
# ---------------------------------------------------------------------------


class _FakeState(dict):
    """Minimal state dict shape the adapter wrappers read."""


@pytest.mark.asyncio
async def test_asgi_verify_wallet_signer_match_no_op_on_operator_token_path() -> None:
    """ASGI wrapper returns pass without calling client when request was operator-token authenticated."""
    from unittest.mock import AsyncMock

    from agentscore_gate.middleware import GATE_STATE_KEY, verify_wallet_signer_match

    fake_client = AsyncMock()
    request = MagicMock()
    request.scope = {
        "state": {GATE_STATE_KEY: {"client": fake_client, "operator_token": "opc_test", "wallet_address": None}},
    }

    result = await verify_wallet_signer_match(request, signer="0xabc")

    assert result.kind == "pass"
    fake_client.averify_wallet_signer_match.assert_not_called()


@pytest.mark.asyncio
async def test_asgi_verify_wallet_signer_match_no_op_when_both_headers_sent() -> None:
    """Section IV: token wins when both headers sent — signer check must no-op."""
    from unittest.mock import AsyncMock

    from agentscore_gate.middleware import GATE_STATE_KEY, verify_wallet_signer_match

    fake_client = AsyncMock()
    request = MagicMock()
    request.scope = {
        "state": {
            GATE_STATE_KEY: {
                "client": fake_client,
                "operator_token": "opc_test",
                "wallet_address": WALLET_A,
            },
        },
    }

    result = await verify_wallet_signer_match(request, signer=WALLET_B)

    assert result.kind == "pass"
    assert result.claimed_operator is None
    fake_client.averify_wallet_signer_match.assert_not_called()


@pytest.mark.asyncio
async def test_asgi_verify_wallet_signer_match_invokes_client_on_wallet_auth() -> None:
    """Strict wallet-auth path — helper calls client and returns its result."""
    from unittest.mock import AsyncMock

    from agentscore_gate.middleware import GATE_STATE_KEY, verify_wallet_signer_match
    from agentscore_gate.types import VerifyWalletSignerResult

    fake_client = AsyncMock()
    fake_client.averify_wallet_signer_match.return_value = VerifyWalletSignerResult(
        kind="wallet_signer_mismatch",
        claimed_operator="op_claimed",
        actual_signer_operator="op_signer",
    )
    request = MagicMock()
    request.scope = {
        "state": {
            GATE_STATE_KEY: {
                "client": fake_client,
                "operator_token": None,
                "wallet_address": WALLET_A,
            },
        },
    }

    result = await verify_wallet_signer_match(request, signer=WALLET_B)

    assert result.kind == "wallet_signer_mismatch"
    fake_client.averify_wallet_signer_match.assert_called_once()


def test_denial_reason_to_body_includes_agent_memory() -> None:
    """TEC-227: the shared serializer marshals agent_memory into the body dict."""
    from agentscore_gate._response import denial_reason_to_body
    from agentscore_gate.types import DenialReason, build_agent_memory_hint

    reason = DenialReason(
        code="missing_identity",
        agent_memory=build_agent_memory_hint("https://api.agentscore.sh"),
    )
    body = denial_reason_to_body(reason)

    assert body["error"] == "missing_identity"
    assert "agent_memory" in body
    assert body["agent_memory"]["save_for_future_agentscore_gates"] is True
    assert "identity_paths" in body["agent_memory"]


def test_denial_reason_to_body_includes_wallet_signer_mismatch_fields() -> None:
    """TEC-226: the shared serializer marshals wallet-signer-match fields into the body."""
    from agentscore_gate._response import denial_reason_to_body
    from agentscore_gate.types import DenialReason

    reason = DenialReason(
        code="wallet_signer_mismatch",
        claimed_operator="op_claimed",
        actual_signer_operator="op_signer",
        expected_signer=WALLET_A.lower(),
        actual_signer=WALLET_B.lower(),
        linked_wallets=[WALLET_A.lower()],
    )
    body = denial_reason_to_body(reason)

    assert body["error"] == "wallet_signer_mismatch"
    assert body["claimed_operator"] == "op_claimed"
    assert body["actual_signer_operator"] == "op_signer"
    assert body["expected_signer"] == WALLET_A.lower()
    assert body["actual_signer"] == WALLET_B.lower()
    assert body["linked_wallets"] == [WALLET_A.lower()]


def test_build_missing_identity_reason_attaches_memory_hint() -> None:
    """TEC-227: the missing_identity builder attaches an agent_memory hint by default."""
    from agentscore_gate._response import build_missing_identity_reason

    reason = build_missing_identity_reason("https://api.agentscore.sh")
    assert reason.code == "missing_identity"
    assert reason.agent_memory is not None
    assert reason.agent_memory.save_for_future_agentscore_gates is True
