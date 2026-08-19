"""Tests des décisions signées Ed25519 (v3.2)."""
import time
import pytest

try:
    from signing import DecisionSigner, DecisionVerifier
    SIGNING_AVAILABLE = True
except ImportError:
    SIGNING_AVAILABLE = False


@pytest.mark.skipif(not SIGNING_AVAILABLE, reason="signing module not installed")
class TestSignedDecisions:
    """Tests de la signature Ed25519."""

    def test_sign_and_verify(self):
        """Une décision signée est correctement vérifiée."""
        signer = DecisionSigner()
        verifier = DecisionVerifier(signer.public_key_pem())

        signed = signer.sign_decision({
            "request_id": "req1",
            "action": "ALLOW",
            "policy_name": "test",
            "policy_version": 1,
            "reason": "ok",
        })
        assert verifier.verify(dict(signed)) is True

    def test_tampered_decision_rejected(self):
        """Un client malveillant ne peut pas modifier DENY → ALLOW."""
        signer = DecisionSigner()
        verifier = DecisionVerifier(signer.public_key_pem())

        signed = signer.sign_decision({
            "request_id": "req1",
            "action": "DENY",
            "policy_name": "test",
            "policy_version": 1,
            "reason": "bad",
        })
        # Attaque : on tente de forcer ALLOW
        signed["action"] = "ALLOW"
        assert verifier.verify(dict(signed)) is False

    def test_expired_decision_rejected(self):
        """Une décision expirée (>5 min) est rejetée."""
        signer = DecisionSigner()
        verifier = DecisionVerifier(signer.public_key_pem())

        signed = signer.sign_decision({
            "request_id": "req1",
            "action": "ALLOW",
            "policy_name": "t",
            "policy_version": 1,
            "reason": "ok",
        })
        # Simule l'expiration
        signed["expires_at"] = int(time.time()) - 10
        assert verifier.verify(dict(signed)) is False

    def test_wrong_key_rejected(self):
        """Une décision signée par une autre clé est rejetée."""
        signer_a = DecisionSigner()
        signer_b = DecisionSigner()
        verifier_a = DecisionVerifier(signer_a.public_key_pem())

        signed_by_b = signer_b.sign_decision({
            "request_id": "r",
            "action": "ALLOW",
            "policy_name": "t",
            "policy_version": 1,
            "reason": "ok",
        })
        assert verifier_a.verify(dict(signed_by_b)) is False

    def test_payload_fields_preserved(self):
        """Le payload signé contient tous les champs attendus."""
        signer = DecisionSigner()
        signed = signer.sign_decision({
            "request_id": "req-abc",
            "action": "ALLOW",
            "policy_name": "finance",
            "policy_version": 42,
            "reason": "within budget",
        })
        assert signed["request_id"] == "req-abc"
        assert signed["action"] == "ALLOW"
        assert signed["policy_name"] == "finance"
        assert signed["policy_version"] == 42
        assert signed["reason"] == "within budget"
        assert "signature" in signed
        assert "issued_at" in signed
        assert "expires_at" in signed
        assert signed["expires_at"] - signed["issued_at"] == 300  # 5 min

    def test_export_import_private_key(self):
        """Une clé exportée/réimportée produit les mêmes signatures."""
        signer1 = DecisionSigner()
        pem = signer1.export_private_pem()

        signer2 = DecisionSigner(pem)
        verifier = DecisionVerifier(signer2.public_key_pem())

        signed = signer1.sign_decision({
            "request_id": "r", "action": "ALLOW",
            "policy_name": "t", "policy_version": 1, "reason": "ok",
        })
        # La clé réimportée doit pouvoir vérifier la signature
        assert verifier.verify(dict(signed)) is True
