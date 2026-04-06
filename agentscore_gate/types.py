from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Grade = Literal["A", "B", "C", "D", "F"]

ScoreStatus = Literal["scored", "stale", "known_unscored"]

DenialCode = Literal["wallet_not_trusted", "missing_wallet_address", "api_error", "payment_required"]


@dataclass
class DenialReason:
    """Reason a request was denied by the gate middleware."""

    code: DenialCode
    decision: str | None = None
    reasons: list[str] = field(default_factory=list)


@dataclass
class ScoreDetail:
    """Typed score breakdown from the assess response."""

    value: float | None
    grade: Grade
    status: ScoreStatus
    confidence: float | None = None
    scored_at: str | None = None
    version: str | None = None
    dimensions: dict[str, Any] | None = None


@dataclass
class Activity:
    """On-chain activity summary from the assess response."""

    total_verified_transactions: int = 0
    total_candidate_transactions: int = 0
    counterparties_count: int = 0
    active_days: int = 0
    active_months: int = 0
    as_verified_payer: int = 0
    as_verified_payee: int = 0
    as_candidate_payer: int = 0
    as_candidate_payee: int = 0
    first_verified_tx_at: str | None = None
    last_verified_tx_at: str | None = None
    first_candidate_tx_at: str | None = None
    last_candidate_tx_at: str | None = None


@dataclass
class Classification:
    """Entity classification from the assess response."""

    entity_type: str | None = None
    confidence: float = 0.0
    is_known: bool = False
    is_known_erc8004_agent: bool = False
    has_verified_payment_activity: bool = False
    has_candidate_payment_activity: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass
class Identity:
    """Known identity links from the assess response."""

    ens_name: str | None = None
    github_url: str | None = None
    website_url: str | None = None


@dataclass
class Reputation:
    """On-chain reputation feedback summary."""

    feedback_count: int = 0
    client_count: int = 0
    trust_avg: float | None = None
    uptime_avg: float | None = None
    activity_avg: float | None = None
    last_feedback_at: str | None = None


@dataclass
class OperatorVerification:
    """Operator verification details from the assess response."""

    level: str = "none"
    operator_type: str | None = None
    claimed_at: str | None = None
    verified_at: str | None = None


@dataclass
class AssessResult:
    """Result from the AgentScore assess API."""

    allow: bool
    decision: str | None = None
    reasons: list[str] = field(default_factory=list)
    score: ScoreDetail | None = None
    activity: Activity | None = None
    classification: Classification | None = None
    identity: Identity | None = None
    reputation: Reputation | None = None
    operator_verification: OperatorVerification | None = None
    resolved_operator: str | None = None
    verify_url: str | None = None
    raw: dict[str, Any] | None = None
