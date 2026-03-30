"""Trust-gating middleware for Python web frameworks using AgentScore."""

from agentscore_gate.client import GateClient
from agentscore_gate.types import Activity, AssessResult, Classification, DenialReason, Grade, Identity, ScoreDetail

# ASGI middleware is the default import.
# Flask and Django adapters are imported from their submodules:
#   from agentscore_gate.flask import agentscore_gate
#   from agentscore_gate.django import AgentScoreMiddleware
try:
    from agentscore_gate.middleware import AgentScoreGate
except ImportError:
    # starlette not installed
    AgentScoreGate = None  # type: ignore[assignment,misc]

__all__ = [
    "Activity",
    "AgentScoreGate",
    "AssessResult",
    "Classification",
    "DenialReason",
    "GateClient",
    "Grade",
    "Identity",
    "ScoreDetail",
]
