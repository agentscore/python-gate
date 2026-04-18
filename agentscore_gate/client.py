"""Shared AgentScore assess client with TTL caching."""

from __future__ import annotations

import json
from importlib.metadata import version as _pkg_version
from typing import Any

import httpx

from agentscore_gate.cache import TTLCache
from agentscore_gate.types import (
    AgentIdentity,
    AssessResult,
    OperatorVerification,
)

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
        require_kyc: bool | None = None,
        require_sanctions_clear: bool | None = None,
        min_age: int | None = None,
        blocked_jurisdictions: list[str] | None = None,
        allowed_jurisdictions: list[str] | None = None,
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
        if require_kyc is not None:
            self._policy["require_kyc"] = require_kyc
        if require_sanctions_clear is not None:
            self._policy["require_sanctions_clear"] = require_sanctions_clear
        if min_age is not None:
            self._policy["min_age"] = min_age
        if blocked_jurisdictions is not None:
            self._policy["blocked_jurisdictions"] = blocked_jurisdictions
        if allowed_jurisdictions is not None:
            self._policy["allowed_jurisdictions"] = allowed_jurisdictions

        self._async_client = httpx.AsyncClient(timeout=10.0)
        self._sync_client = httpx.Client(timeout=10.0)

    def _cache_key(self, address: str | None = None, operator_token: str | None = None) -> str:
        if operator_token:
            return operator_token.lower()
        return (address or "").lower()

    def _build_body(
        self, address: str | None = None, chain: str | None = None, operator_token: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if address:
            body["address"] = address
        if operator_token:
            body["operator_token"] = operator_token
        effective_chain = chain or self._chain
        if effective_chain:
            body["chain"] = effective_chain
        if self._policy:
            body["policy"] = self._policy
        return body

    def _headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self._api_key,
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

        ov_data = data.get("operator_verification")
        operator_verification = (
            OperatorVerification(
                level=ov_data.get("level", "none"),
                operator_type=ov_data.get("operator_type"),
                verified_at=ov_data.get("verified_at"),
            )
            if isinstance(ov_data, dict)
            else None
        )

        return AssessResult(
            allow=allow,
            decision=decision,
            reasons=reasons,
            identity_method=data.get("identity_method"),
            operator_verification=operator_verification,
            resolved_operator=data.get("resolved_operator"),
            verify_url=data.get("verify_url"),
            policy_result=data.get("policy_result"),
            raw=data,
        )

    def check(
        self, address: str | None = None, chain: str | None = None, operator_token: str | None = None
    ) -> AssessResult:
        """Synchronous assess call with caching. Accepts address and/or operator_token."""
        key = self._cache_key(address, operator_token)

        cached = self._cache.get(key)
        if cached is not None:
            return cached

        resp = self._sync_client.post(
            f"{self._base_url}/v1/assess",
            headers=self._headers(),
            content=json.dumps(self._build_body(address, chain, operator_token)),
        )
        result = self._parse_response(resp)
        self._cache.set(key, result)
        return result

    async def acheck(
        self, address: str | None = None, chain: str | None = None, operator_token: str | None = None
    ) -> AssessResult:
        """Asynchronous assess call with caching. Accepts address and/or operator_token."""
        key = self._cache_key(address, operator_token)

        cached = self._cache.get(key)
        if cached is not None:
            return cached

        resp = await self._async_client.post(
            f"{self._base_url}/v1/assess",
            headers=self._headers(),
            content=json.dumps(self._build_body(address, chain, operator_token)),
        )
        result = self._parse_response(resp)
        self._cache.set(key, result)
        return result

    def check_identity(self, identity: AgentIdentity, chain: str | None = None) -> AssessResult:
        """Convenience method to check using an AgentIdentity object."""
        return self.check(address=identity.address, chain=chain, operator_token=identity.operator_token)

    async def acheck_identity(self, identity: AgentIdentity, chain: str | None = None) -> AssessResult:
        """Async convenience method to check using an AgentIdentity object."""
        return await self.acheck(address=identity.address, chain=chain, operator_token=identity.operator_token)


class PaymentRequiredError(Exception):
    """Raised when the AgentScore API returns 402."""
