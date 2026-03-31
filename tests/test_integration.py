import os

import httpx
import pytest

API_KEY = os.environ.get("AGENTSCORE_API_KEY")
BASE_URL = os.environ.get("AGENTSCORE_BASE_URL", "http://api.dev.agentscore.internal")
TEST_ADDRESS = "0x339559a2d1cd15059365fc7bd36b3047bba480e0"

pytestmark = pytest.mark.skipif(not API_KEY, reason="AGENTSCORE_API_KEY not set")


def _assess(body=None):
    return httpx.post(
        f"{BASE_URL}/v1/assess",
        headers={"X-API-Key": API_KEY},
        json={"address": TEST_ADDRESS, **(body or {})},
    ).json()


def test_assess_top_level_shape():
    data = _assess()

    assert isinstance(data["subject"]["chains"], list)
    assert len(data["subject"]["chains"]) > 0

    assert "value" in data["score"]
    assert "grade" in data["score"]
    assert "status" in data["score"]
    assert "version" in data["score"]
    assert "confidence" not in data["score"]
    assert "dimensions" not in data["score"]

    assert isinstance(data["chains"], list)
    assert len(data["chains"]) > 0
    assert isinstance(data["decision_reasons"], list)
    assert isinstance(data["agents"], list)
    assert isinstance(data["caveats"], list)
    assert "data_semantics" in data
    assert "updated_at" in data
    assert "classification" not in data


def test_assess_chain_entry_full_fields():
    data = _assess()
    chain = data["chains"][0]

    assert "confidence" in chain["score"]
    assert "dimensions" in chain["score"]
    assert "entity_type" in chain["classification"]
    assert "ens_name" in chain["identity"]
    assert "as_verified_payer" in chain["activity"]
    assert "active_days" in chain["activity"]
    assert "first_candidate_tx_at" in chain["activity"]
    assert "metadata_kind" in chain["evidence_summary"]


def test_assess_policy_deny():
    data = _assess({"policy": {"min_score": 999}})

    assert data["decision"] == "deny"
    assert len(data["decision_reasons"]) > 0


def test_assess_operator_score():
    data = _assess()
    op = data.get("operator_score")
    if not op:
        pytest.skip("no operator_score on test address")
    assert isinstance(op["score"], int)
    assert isinstance(op["grade"], str)
    assert isinstance(op["agent_count"], int)
    assert isinstance(op["chains_active"], list)
