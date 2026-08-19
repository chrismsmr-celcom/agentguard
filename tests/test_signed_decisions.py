"""Tests des décisions signées Ed25519."""
import time
from signing import DecisionSigner, DecisionVerifier


def test_sign_and_verify():
    signer = DecisionSigner()
    verifier = DecisionVerifier(signer.public_key_pem())

    signed = signer.sign_decision({
        "request_id": "req1", "action": "ALLOW",
        "policy_name": "test", "policy_version": 1, "reason": "ok",
    })
    assert verifier.verify(dict(signed)) is True


def test_tampered_decision_rejected():
    signer = DecisionSigner()
    verifier = DecisionVerifier(signer.public_key_pem())

    signed = signer.sign_decision({
        "request_id": "req1", "action": "DENY",
        "policy_name": "test", "policy_version": 1, "reason": "bad",
    })
    # Attaque : un client malveillant change DENY → ALLOW
    signed["action"] = "ALLOW"
    assert verifier.verify(dict(signed)) is False  # ❌ signature invalide


def test_expired_decision_rejected():
    signer = DecisionSigner()
    verifier = DecisionVerifier(signer.public_key_pem())

    signed = signer.sign_decision({
        "request_id": "req1", "action": "ALLOW",
        "policy_name": "t", "policy_version": 1, "reason": "ok",
    })
    signed["expires_at"] = int(time.time()) - 10  # expiré
    # Re-signe manuellement pour simuler (mais la clé est différente)
    assert verifier.verify(dict(signed)) is False


def test_wrong_key_rejected():
    signer_a = DecisionSigner()
    signer_b = DecisionSigner()
    verifier_a = DecisionVerifier(signer_a.public_key_pem())

    signed_by_b = signer_b.sign_decision({
        "request_id": "r", "action": "ALLOW",
        "policy_name": "t", "policy_version": 1, "reason": "ok",
    })
    # Une décision signée par B ne passe pas la vérification de A
    assert verifier_a.verify(dict(signed_by_b)) is False
