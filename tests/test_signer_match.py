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


def test_agent_memory_hint_custom_base() -> None:
    hint = build_agent_memory_hint("https://api.staging.agentscore.sh")
    assert hint.identity_check_endpoint.startswith("https://api.staging.agentscore.sh")


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
