"""
Cerbere Signed Security Decisions

Ed25519 signatures:
the client cannot forge an ALLOW decision.
"""

import base64
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization


class DecisionSigner:
    """Côté COLLECTOR : signe les décisions de sécurité."""

    def __init__(self, private_key_pem: str | None = None):
        """
        Initialize the signing key.

        Production MUST provide a persistent private key.

        Ephemeral key generation is allowed only when explicitly
        enabled for local development.
        """

        allow_ephemeral = (
            os.getenv(
                "AGENTGUARD_ALLOW_EPHEMERAL_SIGNING_KEY",
                "false",
            ).lower()
            in {"1", "true", "yes", "on"}
        )

        if private_key_pem:
            self._key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
            )

        elif allow_ephemeral:
            self._key = Ed25519PrivateKey.generate()

        else:
            raise RuntimeError(
                "Persistent signing key is required. "
                "Set CERBERE_SIGNING_KEY or "
                "AGENTGUARD_SIGNING_KEY. "
                "For local development only, explicitly set "
                "AGENTGUARD_ALLOW_EPHEMERAL_SIGNING_KEY=true."
            )

        self._public_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def public_key_pem(self) -> str:
        """Return the public key in PEM format."""
        return self._public_pem

    def export_private_pem(self) -> str:
        """
        Export private key.

        WARNING:
        Store this only in CERBERE_SIGNING_KEY or a secret manager.
        """
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def sign_decision(self, decision: dict) -> dict:
        """
        Sign a security decision.

        The signed payload contains only security-authoritative fields.
        """

        now = int(time.time())

        payload = {
            "request_id": decision.get("request_id"),
            "action": decision.get("action"),
            "policy_name": decision.get("policy_name"),
            "policy_version": decision.get("policy_version"),
            "reason": decision.get("reason"),
            "issued_at": now,
            "expires_at": now + 300,
        }

        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

        signature = self._key.sign(
            canonical.encode()
        )

        payload["signature"] = base64.b64encode(
            signature
        ).decode()

        return payload


class DecisionVerifier:
    """Côté SDK : vérifie qu'une décision vient bien du collector."""

    def __init__(self, public_key_pem: str):
        self._pub = serialization.load_pem_public_key(
            public_key_pem.encode()
        )

    def verify(self, signed: dict) -> bool:
        """Verify signature and expiration."""

        if not isinstance(signed, dict):
            return False

        try:
            signature = base64.b64decode(
                signed.get("signature", ""),
                validate=True,
            )
        except Exception:
            return False

        expires_at = signed.get("expires_at")

        try:
            if not expires_at:
                return False

            if float(expires_at) < time.time():
                return False
        except (TypeError, ValueError):
            return False

        payload = {
            key: value
            for key, value in signed.items()
            if key != "signature"
        }

        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

        try:
            self._pub.verify(
                signature,
                canonical.encode(),
            )
            return True

        except Exception:
            return False
