"""Payment-signer extraction.

Pure-x402 extractor for Python. EIP-3009 payment credentials carry the signer at
``payload.authorization.from`` inside a base64-encoded JSON blob — no external deps.

Tempo MPP signer extraction is intentionally not implemented here because there's no
pip-installable equivalent of the node ``mppx`` library today. Merchants that integrate
MPP can extract the signer via their own mppx/Tempo SDK and pass it into
``verify_wallet_signer_match`` explicitly.
"""

from __future__ import annotations

import base64
import json
import re

_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def extract_x402_signer(x402_payment_header: str | None) -> str | None:
    """Decode an x402 ``payment-signature`` / ``x-payment`` header and return the EIP-3009 signer.

    Returns ``None`` when the header is missing, malformed, or carries no ``from`` field.
    """
    if not x402_payment_header:
        return None
    try:
        decoded = base64.b64decode(x402_payment_header, validate=False).decode("utf-8")
        parsed = json.loads(decoded)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    payload = parsed.get("payload")
    if not isinstance(payload, dict):
        return None
    authorization = payload.get("authorization")
    if not isinstance(authorization, dict):
        return None
    sender = authorization.get("from")
    if isinstance(sender, str) and _EVM_RE.match(sender):
        return sender.lower()
    return None
