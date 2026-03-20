"""Shared AgentScore assess client with TTL caching."""

from __future__ import annotations

import json
from typing import Any

import httpx

from agentscore_gate.cache import TTLCache
from agentscore_gate.types import AssessResult, Grade

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
    ) -> None:
        if not api_key:
            msg = "AgentScore API key is required. Get one at https://agentscore.sh/sign-up"
            raise ValueError(msg)

        self.fail_open = fail_open
        self._api_key = api_key
        self._base_url = base_url
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

    def _cache_key(self, address: str, chain: str) -> str:
        return f"{chain}:{address.lower()}"

    def _build_body(self, address: str, chain: str) -> dict[str, Any]:
        body: dict[str, Any] = {"address": address, "chain": chain}
        if self._policy:
            body["policy"] = self._policy
        return body

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
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

        return AssessResult(allow=allow, decision=decision, reasons=reasons, raw=data)

    def check(self, address: str, chain: str = "base") -> AssessResult:
        """Synchronous assess call with caching."""
        key = self._cache_key(address, chain)

        cached = self._cache.get(key)
        if cached is not None:
            return cached

        resp = self._sync_client.post(
            f"{self._base_url}/v1/assess",
            headers=self._headers(),
            content=json.dumps(self._build_body(address, chain)),
        )
        result = self._parse_response(resp)
        self._cache.set(key, result)
        return result

    async def acheck(self, address: str, chain: str = "base") -> AssessResult:
        """Asynchronous assess call with caching."""
        key = self._cache_key(address, chain)

        cached = self._cache.get(key)
        if cached is not None:
            return cached

        resp = await self._async_client.post(
            f"{self._base_url}/v1/assess",
            headers=self._headers(),
            content=json.dumps(self._build_body(address, chain)),
        )
        result = self._parse_response(resp)
        self._cache.set(key, result)
        return result


class PaymentRequiredError(Exception):
    """Raised when the AgentScore API returns 402."""
