# Vulture whitelist — false positives

# Middleware __call__ ASGI signature
scope  # noqa: F821
receive  # noqa: F821
send  # noqa: F821

# Public API exports
Activity  # noqa: F821
AgentScoreGate  # noqa: F821
AssessResult  # noqa: F821
Classification  # noqa: F821
DenialReason  # noqa: F821
Grade  # noqa: F821
Identity  # noqa: F821
Reputation  # noqa: F821
ScoreDetail  # noqa: F821
ScoreStatus  # noqa: F821
OperatorVerification  # noqa: F821

# Dataclass fields — accessed by consumers, not internally
grade  # noqa: F821
scored_at  # noqa: F821
dimensions  # noqa: F821
total_verified_transactions  # noqa: F821
total_candidate_transactions  # noqa: F821
counterparties_count  # noqa: F821
active_days  # noqa: F821
active_months  # noqa: F821
as_verified_payer  # noqa: F821
as_verified_payee  # noqa: F821
as_candidate_payer  # noqa: F821
as_candidate_payee  # noqa: F821
first_verified_tx_at  # noqa: F821
last_verified_tx_at  # noqa: F821
first_candidate_tx_at  # noqa: F821
last_candidate_tx_at  # noqa: F821
entity_type  # noqa: F821
confidence  # noqa: F821
is_known  # noqa: F821
is_known_erc8004_agent  # noqa: F821
has_verified_payment_activity  # noqa: F821
has_candidate_payment_activity  # noqa: F821
ens_name  # noqa: F821
github_url  # noqa: F821
website_url  # noqa: F821
feedback_count  # noqa: F821
client_count  # noqa: F821
trust_avg  # noqa: F821
uptime_avg  # noqa: F821
activity_avg  # noqa: F821
last_feedback_at  # noqa: F821
level  # noqa: F821
operator_type  # noqa: F821
verified_at  # noqa: F821
resolved_operator  # noqa: F821
verify_url  # noqa: F821
identity_method  # noqa: F821
policy_result  # noqa: F821
rule  # noqa: F821
passed  # noqa: F821
required  # noqa: F821
actual  # noqa: F821
all_passed  # noqa: F821
checks  # noqa: F821
PolicyCheck  # noqa: F821
PolicyResult  # noqa: F821

# Django adapter — used by consumers via settings.py MIDDLEWARE
AgentScoreMiddleware  # noqa: F821
agentscore  # noqa: F821

# Flask adapter — used by consumers, registered via before_request
agentscore_gate  # noqa: F821
_agentscore_check  # noqa: F821

# Test fixtures — used by test frameworks, not called directly
return_value  # noqa: F821
urlpatterns  # noqa: F821
index  # noqa: F821
