# Vulture whitelist — false positives

# Middleware __call__ ASGI signature
scope  # noqa: F821
receive  # noqa: F821
send  # noqa: F821

# Public API exports
AgentScoreGate  # noqa: F821
AssessResult  # noqa: F821
DenialReason  # noqa: F821
Grade  # noqa: F821

# Django adapter — used by consumers via settings.py MIDDLEWARE
AgentScoreMiddleware  # noqa: F821
agentscore  # noqa: F821

# Flask adapter — used by consumers, registered via before_request
agentscore_gate  # noqa: F821
_agentscore_check  # noqa: F821
