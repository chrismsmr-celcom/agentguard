"""
AgentGuard ML Detector — single source of truth (v4 benchmark-tuned).

Fixes v3.1 :
- import re manquant (crash au boot)
- Thread-safety (lock inference pour Gunicorn multi-threads)
- Garde-fou longueur d'input optimisé (anti-DoS tokenizer)
- FP16 auto sur CUDA (inference ~2x plus rapide)
- Logging structure et validation stricte des labels du modele

Fixes v4 (benchmark 2026-09-26, layers regex,ml) :
- Threshold par defaut 0.95 (etait 0.85). Dans la cascade, le ML ne voit QUE
  ce que le regex a laisse passer : sa barre doit etre haute. A 0.85 le run
  benchmark donnait FPR benin 5% et hard-neg 33% ; a 0.95 la cible est 0%.
- Double passe normalisee : le classifier score le texte brut ET sa version
  de-obfusquee (agentguard.normalizer) et garde le max. Sans ça, le ML rate
  les homoglyphes/zero-width qu'il n'a jamais vus a l'entrainement
  (encoded_obfuscated 8/10 au lieu de 10/10).
- Version de modele loggee au boot (reproductibilite du benchmark).
"""
import os
import re
import logging
import threading
from typing import Dict, Any

logger = logging.getLogger("agentguard.ml")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class MLDetector:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self._lock = threading.Lock()          # thread-safety inference
        self.enabled = os.getenv("AGENTGUARD_USE_ML", "false").lower() in ("true", "1", "yes")
        # v4: seuil dur. Le ML est un second filtre, pas un premier filtre.
        self.threshold = self._float_env("AGENTGUARD_ML_THRESHOLD", 0.95, 0.0, 1.0)
        self.model_path = os.getenv("AGENTGUARD_MODEL_PATH", "./agentguard-model")
        self.model_name = os.getenv(
            "AGENTGUARD_MODEL_NAME",
            "protectai/deberta-v3-base-prompt-injection-v2",
        )
        self.max_chars = int(os.getenv("AGENTGUARD_ML_MAX_CHARS", "8192"))
        # v4: double passe normalisee (desactivable pour le debug)
        self.dual_pass = os.getenv("AGENTGUARD_ML_DUAL_PASS", "true").lower() in ("true", "1", "yes")
        self._normalizer = None
        self.attack_label_id = None
        self.benign_label_id = None
        self.model_labels = {}

        if not self.enabled or not TORCH_AVAILABLE:
            if not TORCH_AVAILABLE and self.enabled:
                logger.warning("ml_disabled_torch_absent")
            return

        try:
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
            )

            self.device = "cuda" if torch.cuda.is_available() else "cpu"

            local_loaded = False
            if os.path.exists(self.model_path):
                try:
                    logger.info("ml_model_local_load", path=self.model_path)
                    local_tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                    local_model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
                    labels = self._validate_model_labels(local_model)
                    self.tokenizer = local_tokenizer
                    self.model = local_model
                    self._set_model_label_ids(labels)
                    local_loaded = True
                except Exception as exc:
                    logger.warning(
                        "ml_local_model_incompatible",
                        error=f"{type(exc).__name__}: {exc}",
                    )

            if not local_loaded:
                logger.info("ml_model_download", model=self.model_name)
                remote_tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                remote_model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
                labels = self._validate_model_labels(remote_model)
                self.tokenizer = remote_tokenizer
                self.model = remote_model
                self._set_model_label_ids(labels)

                try:
                    os.makedirs(self.model_path, exist_ok=True)
                    self.model.save_pretrained(self.model_path)
                    self.tokenizer.save_pretrained(self.model_path)
                    logger.info("ml_model_cached", path=self.model_path)
                except Exception as save_err:
                    logger.warning("ml_model_cache_failed", error=str(save_err))

            self.model.to(self.device)

            # FP16 sur GPU uniquement (CPU ne le supporte pas nativement de maniere stable)
            if self.device == "cuda":
                self.model.half()
            self.model.eval()

            # v4: chargement paresseux du normalizer (source unique de verite)
            if self.dual_pass:
                try:
                    from agentguard.normalizer import normalize_for_detection
                    self._normalizer = normalize_for_detection
                except Exception:
                    logger.warning("ml_normalizer_unavailable_dual_pass_disabled")
                    self.dual_pass = False

            logger.info(
                "ml_enabled",
                device=self.device,
                threshold=self.threshold,
                model=self.model_name,
                dual_pass=self.dual_pass,
                attack_label_id=self.attack_label_id,
                benign_label_id=self.benign_label_id,
            )

        except Exception as exc:
            logger.warning("ml_load_failed", error=str(exc))
            self.enabled = False

    @staticmethod
    def _normalize_label(label):
        return re.sub(r"[^a-z0-9]+", "_", str(label).strip().lower()).strip("_")

    def _validate_model_labels(self, model):
        """Valide qu'un modele est compatible avec le contrat de securite."""
        config = getattr(model, "config", None)
        raw_labels = getattr(config, "id2label", {}) or {}

        normalized = {}
        for key, value in raw_labels.items():
            try:
                idx = int(key)
            except (TypeError, ValueError):
                continue
            normalized[idx] = self._normalize_label(value)

        if len(normalized) < 2:
            raise RuntimeError(f"Classifier labels missing or invalid: {raw_labels!r}")

        attack_labels = {
            "injection", "prompt_injection", "jailbreak",
            "malicious", "unsafe", "attack", "attacker",
        }
        benign_labels = {
            "safe", "benign", "no_injection", "clean", "normal", "non_injection",
        }

        attack_ids = [i for i, l in normalized.items() if l in attack_labels]
        benign_ids = [i for i, l in normalized.items() if l in benign_labels]

        if len(attack_ids) != 1 or len(benign_ids) != 1:
            raise RuntimeError(
                f"Incompatible security classifier labels: {normalized}. "
                "Expected exactly one benign label and one attack/injection label."
            )

        return {
            "id2label": normalized,
            "attack_label_id": attack_ids[0],
            "benign_label_id": benign_ids[0],
        }

    def _set_model_label_ids(self, labels):
        self.model_labels = labels["id2label"]
        self.attack_label_id = labels["attack_label_id"]
        self.benign_label_id = labels["benign_label_id"]

    @staticmethod
    def _float_env(name, default, low, high):
        try:
            return max(low, min(high, float(os.getenv(name, str(default)))))
        except (TypeError, ValueError):
            return default

    def _score_once(self, text: str) -> float:
        """Une seule inference, thread-safe. Retourne le score d'attaque."""
        text = str(text or "")[: self.max_chars]

        with self._lock:
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                logits = self.model(**inputs).logits
                probabilities = torch.softmax(logits, dim=1)

        if self.attack_label_id is None:
            raise RuntimeError("ML security classifier has no validated attack label")

        return float(probabilities[0][self.attack_label_id].item())

    def predict(self, text: str) -> Dict[str, Any]:
        if not self.enabled or self.model is None or self.tokenizer is None:
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}

        try:
            text = str(text or "")

            # v4: passe brute
            score = self._score_once(text)

            # v4: passe normalisee — seulement si le normalizer change le texte
            # (early exit : le trafic propre ne paie qu'une seule inference).
            if self.dual_pass and self._normalizer is not None:
                normalized = self._normalizer(text)
                if normalized != text:
                    norm_score = self._score_once(normalized)
                    if norm_score > score:
                        score = norm_score

            if score >= self.threshold:
                risk = "HIGH"
            elif score >= max(0.0, self.threshold - 0.15):
                risk = "MEDIUM"
            else:
                risk = "LOW"

            confidence = "high" if score >= 0.9 or score <= 0.1 else "medium"

            return {"score": score, "risk": risk, "confidence": confidence}

        except Exception as exc:
            logger.warning("ml_predict_error", error=str(exc))
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}
