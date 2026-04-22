"""Trust-gating middleware for Python web frameworks using AgentScore."""

from typing import Any

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
def _load_asgi_middleware() -> tuple[Any, Any]:
    try:
        from agentscore_gate.middleware import AgentScoreGate as _AgentScoreGate
        from agentscore_gate.middleware import CreateSessionOnMissing as _CreateSessionOnMissing

        return _AgentScoreGate, _CreateSessionOnMissing
    except ImportError:
        # starlette not installed
        return None, None


AgentScoreGate, CreateSessionOnMissing = _load_asgi_middleware()

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
