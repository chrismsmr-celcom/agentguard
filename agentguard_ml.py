"""
AgentGuard ML Detector — single source of truth (v3.0 prod-ready).

Fixes v3.0 :
✅ import re manquant (crash au boot)
✅ Thread-safety (lock inference pour Gunicorn multi-threads)
✅ Garde-fou longueur d'input (anti-DoS tokenizer)
✅ FP16 auto sur CUDA (inférence ~2x plus rapide)
✅ Logging structuré au lieu de warnings
"""

import os
import re                       # ← FIX CRITIQUE (manquait)
import logging
import threading
from typing import Dict, Any

logger = logging.getLogger("agentguard.ml")


class MLDetector:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self._lock = threading.Lock()          # thread-safety inference
        self.enabled = os.getenv("AGENTGUARD_USE_ML", "false").lower() == "true"
        self.threshold = self._float_env("AGENTGUARD_ML_THRESHOLD", 0.85, 0.0, 1.0)
        self.model_path = os.getenv("AGENTGUARD_MODEL_PATH", "./agentguard-model")
        self.model_name = os.getenv(
            "AGENTGUARD_MODEL_NAME",
            "protectai/deberta-v3-base-prompt-injection-v2",
        )
        self.max_chars = int(os.getenv("AGENTGUARD_ML_MAX_CHARS", "20000"))
        self.attack_label_id = None
        self.benign_label_id = None
        self.model_labels = {}

        if not self.enabled:
            return

        try:
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
            )
            import torch
            self._torch = torch

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
            # FP16 sur GPU uniquement (CPU ne le supporte pas bien)
            if self.device == "cuda":
                self.model.half()
            self.model.eval()

            logger.info(
                "ml_enabled",
                device=self.device,
                threshold=self.threshold,
                model=self.model_name,
                attack_label=self.attack_label_id,
            )

        except ImportError:
            logger.warning("ml_disabled_transformers_absent")
            self.enabled = False
        except Exception as exc:
            logger.warning("ml_load_failed", error=str(exc))
            self.enabled = False

    @staticmethod
    def _normalize_label(label):
        return re.sub(r"[^a-z0-9]+", "_", str(label).strip().lower()).strip("_")

    def _validate_model_labels(self, model):
        """Valide qu'un modèle est compatible avec le contrat de sécurité."""
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

    def predict(self, text: str) -> Dict[str, Any]:
        if not self.enabled or self.model is None:
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}

        try:
            text = str(text or "")[: self.max_chars]   # garde-fou anti-DoS
            torch = self._torch

            with self._lock:   # inference thread-safe
                inputs = self.tokenizer(
                    text, return_tensors="pt", truncation=True,
                    max_length=512, padding=True,
                )
                inputs = {k: v.to(self.device) for k, v in inputs.items()}

                with torch.no_grad():
                    probabilities = torch.softmax(self.model(**inputs).logits, dim=1)

            if self.attack_label_id is None:
                raise RuntimeError("ML security classifier has no validated attack label")

            score = float(probabilities[0][self.attack_label_id].item())

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
