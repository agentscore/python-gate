from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Grade = Literal["A", "B", "C", "D", "F"]

DenialCode = Literal["wallet_not_trusted", "missing_wallet_address", "api_error", "payment_required"]


@dataclass
class DenialReason:
    """Reason a request was denied by the gate middleware."""

    code: DenialCode
    decision: str | None = None
    reasons: list[str] = field(default_factory=list)


@dataclass
class AssessResult:
    """Internal result from the AgentScore assess API."""

    allow: bool
    decision: str | None = None
    reasons: list[str] = field(default_factory=list)
    raw: dict[str, Any] | None = None
