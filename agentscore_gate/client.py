"""Shared AgentScore assess client with TTL caching."""

from __future__ import annotations

import json
from importlib.metadata import version as _pkg_version
from typing import Any

import httpx

from agentscore_gate.cache import TTLCache
from agentscore_gate.types import Activity, AssessResult, Classification, Grade, Identity, Reputation, ScoreDetail

DEFAULT_BASE_URL = "https://api.agentscore.sh"
DEFAULT_CACHE_SECONDS = 300


class GateClient:
    """Shared client for calling the AgentScore assess API.

    Manages caching and policy construction. Used by all framework adapters.
    """

    def __init__(
        self,
        *,
        api_key: str,
        min_grade: Grade | None = None,
        min_score: int | None = None,
        require_verified_activity: bool | None = None,
        fail_open: bool = False,
        cache_seconds: int = DEFAULT_CACHE_SECONDS,
        base_url: str = DEFAULT_BASE_URL,
        chain: str | None = None,
    ) -> None:
        if not api_key:
            msg = "AgentScore API key is required. Get one at https://agentscore.sh/sign-up"
            raise ValueError(msg)

        self.fail_open = fail_open
        self._api_key = api_key
        self._base_url = base_url
        self._chain = chain
        self._cache: TTLCache[AssessResult] = TTLCache(cache_seconds)

        self._policy: dict[str, Any] = {}
        if min_grade is not None:
            self._policy["min_grade"] = min_grade
        if min_score is not None:
            self._policy["min_score"] = min_score
        if require_verified_activity is not None:
            self._policy["require_verified_payment_activity"] = require_verified_activity

        self._async_client = httpx.AsyncClient(timeout=10.0)
        self._sync_client = httpx.Client(timeout=10.0)

    def _cache_key(self, address: str) -> str:
        return address.lower()

    def _build_body(self, address: str) -> dict[str, Any]:
        body: dict[str, Any] = {"address": address}
        if self._chain:
            body["chain"] = self._chain
        if self._policy:
            body["policy"] = self._policy
        return body

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"agentscore-gate-py/{_pkg_version('agentscore-gate')}",
        }

    def _parse_response(self, resp: httpx.Response) -> AssessResult:
        if resp.status_code == 402:
            raise PaymentRequiredError

        if not resp.is_success:
            msg = f"AgentScore API returned {resp.status_code}"
            raise RuntimeError(msg)

        data: dict[str, Any] = resp.json()
        decision = data.get("decision")
        reasons: list[str] = data.get("decision_reasons", [])
        allow = decision == "allow" or decision is None

        score_data = data.get("score")
        score = (
            ScoreDetail(
                value=score_data.get("value", 0),
                grade=score_data.get("grade", "F"),
                status=score_data.get("status", "pending"),
                confidence=score_data.get("confidence", 0.0),
                scored_at=score_data.get("scored_at"),
                version=score_data.get("version"),
                dimensions=score_data.get("dimensions", {}),
            )
            if isinstance(score_data, dict)
            else None
        )

        chains = data.get("chains", [])
        first_chain = chains[0] if chains else {}

        act_data = first_chain.get("activity") if isinstance(first_chain, dict) else None
        activity = (
            Activity(
                total_verified_transactions=act_data.get("total_verified_transactions", 0),
                total_candidate_transactions=act_data.get("total_candidate_transactions", 0),
                counterparties_count=act_data.get("counterparties_count", 0),
                active_days=act_data.get("active_days", 0),
                active_months=act_data.get("active_months", 0),
                as_verified_payer=act_data.get("as_verified_payer", 0),
                as_verified_payee=act_data.get("as_verified_payee", 0),
                as_candidate_payer=act_data.get("as_candidate_payer", 0),
                as_candidate_payee=act_data.get("as_candidate_payee", 0),
                first_verified_tx_at=act_data.get("first_verified_tx_at"),
                last_verified_tx_at=act_data.get("last_verified_tx_at"),
                first_candidate_tx_at=act_data.get("first_candidate_tx_at"),
                last_candidate_tx_at=act_data.get("last_candidate_tx_at"),
            )
            if isinstance(act_data, dict)
            else None
        )

        top_cls = data.get("classification") if isinstance(data.get("classification"), dict) else {}
        chain_cls = first_chain.get("classification", {}) if isinstance(first_chain, dict) else {}
        cls_data = {**chain_cls, **top_cls} if (top_cls or chain_cls) else None
        classification = (
            Classification(
                entity_type=cls_data.get("entity_type"),
                confidence=cls_data.get("confidence", 0.0),
                is_known=cls_data.get("is_known", False),
                is_known_erc8004_agent=cls_data.get("is_known_erc8004_agent", False),
                has_verified_payment_activity=cls_data.get("has_verified_payment_activity", False),
                has_candidate_payment_activity=cls_data.get("has_candidate_payment_activity", False),
                reasons=cls_data.get("reasons", []),
            )
            if isinstance(cls_data, dict)
            else None
        )

        id_data = first_chain.get("identity") if isinstance(first_chain, dict) else None
        identity = (
            Identity(
                ens_name=id_data.get("ens_name"),
                github_url=id_data.get("github_url"),
                website_url=id_data.get("website_url"),
            )
            if isinstance(id_data, dict)
            else None
        )

        rep_data = data.get("reputation")
        reputation = (
            Reputation(
                feedback_count=rep_data.get("feedback_count", 0),
                client_count=rep_data.get("client_count", 0),
                trust_avg=rep_data.get("trust_avg"),
                uptime_avg=rep_data.get("uptime_avg"),
                activity_avg=rep_data.get("activity_avg"),
                last_feedback_at=rep_data.get("last_feedback_at"),
            )
            if isinstance(rep_data, dict)
            else None
        )

        return AssessResult(
            allow=allow,
            decision=decision,
            reasons=reasons,
            score=score,
            activity=activity,
            classification=classification,
            identity=identity,
            reputation=reputation,
            raw=data,
        )

    def check(self, address: str) -> AssessResult:
        """Synchronous assess call with caching."""
        key = self._cache_key(address)

        cached = self._cache.get(key)
        if cached is not None:
            return cached

        resp = self._sync_client.post(
            f"{self._base_url}/v1/assess",
            headers=self._headers(),
            content=json.dumps(self._build_body(address)),
        )
        result = self._parse_response(resp)
        self._cache.set(key, result)
        return result

    async def acheck(self, address: str) -> AssessResult:
        """Asynchronous assess call with caching."""
        key = self._cache_key(address)

        cached = self._cache.get(key)
        if cached is not None:
            return cached

        resp = await self._async_client.post(
            f"{self._base_url}/v1/assess",
            headers=self._headers(),
            content=json.dumps(self._build_body(address)),
        )
        result = self._parse_response(resp)
        self._cache.set(key, result)
        return result


class PaymentRequiredError(Exception):
    """Raised when the AgentScore API returns 402."""
