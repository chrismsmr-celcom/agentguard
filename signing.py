"""
Cerbere Signed Security Decisions
Signature Ed25519 : aucun client ne peut forger une décision ALLOW.
"""
import base64
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization


class DecisionSigner:
    """Côté COLLECTOR : signe les décisions de sécurité."""

    def __init__(self, private_key_pem: str = None):
        if private_key_pem:
            self._key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=None
            )
        else:
            self._key = Ed25519PrivateKey.generate()

        self._public_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def public_key_pem(self) -> str:
        return self._public_pem

    def export_private_pem(self) -> str:
        """À stocker dans CERBERE_SIGNING_KEY (secret!)."""
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def sign_decision(self, decision: dict) -> dict:
        now = int(time.time())
        payload = {
            "request_id": decision.get("request_id"),
            "action": decision.get("action"),
            "policy_name": decision.get("policy_name"),
            "policy_version": decision.get("policy_version"),
            "reason": decision.get("reason"),
            "issued_at": now,
            "expires_at": now + 300,  # 5 min de validité
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sig = self._key.sign(canonical.encode())
        payload["signature"] = base64.b64encode(sig).decode()
        return payload


class DecisionVerifier:
    """Côté SDK : vérifie qu'une décision vient bien du collector."""

    def __init__(self, public_key_pem: str):
        self._pub = serialization.load_pem_public_key(public_key_pem.encode())

    def verify(self, signed: dict) -> bool:
        try:
            sig = base64.b64decode(signed.get("signature", ""))
        except Exception:
            return False

        # Expiration
        if signed.get("expires_at", 0) < time.time():
            return False

        # Reconstruit le payload signé (sans la signature)
        payload = {k: v for k, v in signed.items() if k != "signature"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        try:
            self._pub.verify(sig, canonical.encode())
            return True
        except Exception:
            return False
