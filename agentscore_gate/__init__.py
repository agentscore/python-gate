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

# ASGI middleware is the default import (re-exported as CreateSessionOnMissing too).
# Framework adapters are imported from their own submodules:
#   from agentscore_gate.fastapi import AgentScoreGate, get_assess_data  # native Depends()
#   from agentscore_gate.flask import agentscore_gate
#   from agentscore_gate.django import AgentScoreMiddleware
#   from agentscore_gate.aiohttp import agentscore_gate_middleware
#   from agentscore_gate.sanic import agentscore_gate
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
