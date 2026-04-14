"""Trust-gating middleware for Python web frameworks using AgentScore."""

from agentscore_gate.client import GateClient
from agentscore_gate.types import (
    Activity,
    AgentIdentity,
    AssessResult,
    Classification,
    DenialReason,
    Grade,
    Identity,
    OperatorVerification,
    ScoreDetail,
)

# ASGI middleware is the default import.
# Flask and Django adapters are imported from their submodules:
#   from agentscore_gate.flask import agentscore_gate
#   from agentscore_gate.django import AgentScoreMiddleware
try:
    from agentscore_gate.middleware import AgentScoreGate, CreateSessionOnMissing
except ImportError:
    # starlette not installed
    AgentScoreGate = None  # type: ignore[assignment,misc]
    CreateSessionOnMissing = None  # type: ignore[assignment,misc]

__all__ = [
    "Activity",
    "AgentIdentity",
    "AgentScoreGate",
    "AssessResult",
    "Classification",
    "CreateSessionOnMissing",
    "DenialReason",
    "GateClient",
    "Grade",
    "Identity",
    "OperatorVerification",
    "ScoreDetail",
]
