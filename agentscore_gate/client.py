"""Shared AgentScore assess client with TTL caching."""

from __future__ import annotations

import contextlib
import json
from importlib.metadata import version as _pkg_version
from typing import Any

import httpx

from agentscore_gate.cache import TTLCache
from agentscore_gate.types import (
    AgentIdentity,
    AssessResult,
    Network,
    OperatorVerification,
    VerifyWalletSignerMatchOptions,
    VerifyWalletSignerResult,
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
        user_agent: str | None = None,
    ) -> None:
        if not api_key:
            msg = "AgentScore API key is required. Get one at https://agentscore.sh/sign-up"
            raise ValueError(msg)

        self.fail_open = fail_open
        self._api_key = api_key
        self._base_url = base_url
        # Public accessor so adapters can build agent_memory hints pointing at the same API.
        self.base_url = base_url
        self._chain = chain
        default_ua = f"agentscore-gate/{_pkg_version('agentscore-gate')}"
        self.user_agent = f"{user_agent} ({default_ua})" if user_agent else default_ua
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
            "User-Agent": self.user_agent,
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

    def capture_wallet(
        self,
        operator_token: str,
        wallet_address: str,
        network: Network,
        idempotency_key: str | None = None,
    ) -> None:
        """Report a wallet seen paying under an operator credential (TEC-189).

        Fire-and-forget: silently swallows non-fatal errors. ``idempotency_key`` (payment intent
        id, tx hash, …) lets the server dedupe agent retries of the same logical payment.
        """
        body: dict[str, Any] = {
            "operator_token": operator_token,
            "wallet_address": wallet_address,
            "network": network,
        }
        if idempotency_key:
            body["idempotency_key"] = idempotency_key
        # Silent — capture is fire-and-forget
        with contextlib.suppress(Exception):
            self._sync_client.post(
                f"{self._base_url}/v1/credentials/wallets",
                headers=self._headers(),
                content=json.dumps(body),
            )

    async def acapture_wallet(
        self,
        operator_token: str,
        wallet_address: str,
        network: Network,
        idempotency_key: str | None = None,
    ) -> None:
        """Async variant of :meth:`capture_wallet`."""
        body: dict[str, Any] = {
            "operator_token": operator_token,
            "wallet_address": wallet_address,
            "network": network,
        }
        if idempotency_key:
            body["idempotency_key"] = idempotency_key
        # Silent — capture is fire-and-forget
        with contextlib.suppress(Exception):
            await self._async_client.post(
                f"{self._base_url}/v1/credentials/wallets",
                headers=self._headers(),
                content=json.dumps(body),
            )

    # ------------------------------------------------------------------
    # TEC-226 — wallet-auth signer binding
    # ------------------------------------------------------------------

    def _resolve_from_cache(self, wallet: str) -> tuple[bool, str | None]:
        """Look up a wallet in either cache. Returns (hit, operator). hit=False means miss."""
        for key in (wallet, f"resolve:{wallet}"):
            cached = self._cache.get(key)
            if cached is not None:
                raw = cached.raw or {}
                op = raw.get("resolved_operator")
                if op is None or isinstance(op, str):
                    return True, op
        return False, None

    def _resolve_wallet_to_operator(self, wallet_address: str) -> tuple[bool, str | None]:
        """Resolve a wallet to its operator id via /v1/assess.

        Returns ``(ok, operator)``:
        - ``(True, <id>)``: wallet linked to that operator
        - ``(True, None)``: wallet is valid but unlinked
        - ``(False, None)``: transient API failure (network / non-2xx). Caller should emit
          an ``api_error`` result rather than silently assert the wallet is unlinked.

        Checks both the main evaluate cache and the resolve-specific cache before calling
        the API — saves a second /v1/assess when the gate already resolved this wallet
        during identity evaluation.
        """
        wallet = wallet_address.lower()
        hit, op = self._resolve_from_cache(wallet)
        if hit:
            return True, op
        try:
            resp = self._sync_client.post(
                f"{self._base_url}/v1/assess",
                headers=self._headers(),
                content=json.dumps({"address": wallet_address}),
            )
        except httpx.HTTPError:
            return False, None
        if not resp.is_success:
            return False, None
        data: dict[str, Any] = resp.json()
        self._cache.set(f"resolve:{wallet}", AssessResult(allow=True, raw=data))
        op_value = data.get("resolved_operator")
        return True, op_value if isinstance(op_value, str) else None

    async def _aresolve_wallet_to_operator(self, wallet_address: str) -> tuple[bool, str | None]:
        wallet = wallet_address.lower()
        hit, op = self._resolve_from_cache(wallet)
        if hit:
            return True, op
        try:
            resp = await self._async_client.post(
                f"{self._base_url}/v1/assess",
                headers=self._headers(),
                content=json.dumps({"address": wallet_address}),
            )
        except httpx.HTTPError:
            return False, None
        if not resp.is_success:
            return False, None
        data: dict[str, Any] = resp.json()
        self._cache.set(f"resolve:{wallet}", AssessResult(allow=True, raw=data))
        op_value = data.get("resolved_operator")
        return True, op_value if isinstance(op_value, str) else None

    def verify_wallet_signer_match(self, options: VerifyWalletSignerMatchOptions) -> VerifyWalletSignerResult:
        """Verify payment signer resolves to the same operator as the claimed wallet (TEC-226).

        Returns:
            ``kind='pass'`` when the signer is the claimed wallet (byte-equal) or both resolve
            to the same operator. ``kind='wallet_signer_mismatch'`` when operators differ.
            ``kind='wallet_auth_requires_wallet_signing'`` when ``signer`` is ``None`` (SPT/card).
            ``kind='api_error'`` when /v1/assess resolve failed — caller should retry or surface
            as 503; distinct from mismatch so legitimate users aren't rejected on network flakes.
        """
        signer = options.signer
        if signer is None:
            return VerifyWalletSignerResult(
                kind="wallet_auth_requires_wallet_signing",
                claimed_wallet=options.claimed_wallet,
            )
        claimed = options.claimed_wallet.lower()
        signer_lower = signer.lower()
        if claimed == signer_lower:
            return VerifyWalletSignerResult(kind="pass")
        claimed_ok, claimed_op = self._resolve_wallet_to_operator(claimed)
        signer_ok, signer_op = self._resolve_wallet_to_operator(signer_lower)
        if not claimed_ok or not signer_ok:
            return VerifyWalletSignerResult(kind="api_error", claimed_wallet=claimed)
        if claimed_op and signer_op and claimed_op == signer_op:
            return VerifyWalletSignerResult(kind="pass", claimed_operator=claimed_op, signer_operator=signer_op)
        return VerifyWalletSignerResult(
            kind="wallet_signer_mismatch",
            claimed_operator=claimed_op,
            actual_signer_operator=signer_op,
            expected_signer=claimed,
            actual_signer=signer_lower,
            linked_wallets=[],
        )

    async def averify_wallet_signer_match(self, options: VerifyWalletSignerMatchOptions) -> VerifyWalletSignerResult:
        """Async variant of :meth:`verify_wallet_signer_match`."""
        signer = options.signer
        if signer is None:
            return VerifyWalletSignerResult(
                kind="wallet_auth_requires_wallet_signing",
                claimed_wallet=options.claimed_wallet,
            )
        claimed = options.claimed_wallet.lower()
        signer_lower = signer.lower()
        if claimed == signer_lower:
            return VerifyWalletSignerResult(kind="pass")
        claimed_ok, claimed_op = await self._aresolve_wallet_to_operator(claimed)
        signer_ok, signer_op = await self._aresolve_wallet_to_operator(signer_lower)
        if not claimed_ok or not signer_ok:
            return VerifyWalletSignerResult(kind="api_error", claimed_wallet=claimed)
        if claimed_op and signer_op and claimed_op == signer_op:
            return VerifyWalletSignerResult(kind="pass", claimed_operator=claimed_op, signer_operator=signer_op)
        return VerifyWalletSignerResult(
            kind="wallet_signer_mismatch",
            claimed_operator=claimed_op,
            actual_signer_operator=signer_op,
            expected_signer=claimed,
            actual_signer=signer_lower,
            linked_wallets=[],
        )


class PaymentRequiredError(Exception):
    """Raised when the AgentScore API returns 402."""
