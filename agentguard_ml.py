"""
AgentGuard ML Detector — Unifié et optimisé
Utilisé par agentguard_sdk.py::MLDetector
"""

import os
import warnings
from functools import lru_cache

class MLDetector:
    """
    Détecteur d'injection basé sur un modèle fine-tuné (DistilBERT/RoBERTa).
    Désactivé par défaut, ne charge rien tant que AGENTGUARD_USE_ML=true.
    """
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self.threshold = float(os.environ.get("AGENTGUARD_ML_THRESHOLD", "0.85"))
        self.enabled = os.environ.get("AGENTGUARD_USE_ML", "false").lower() == "true"
        self.model_path = os.environ.get("AGENTGUARD_MODEL_PATH", "./agentguard-model")
        
        if not self.enabled:
            return
            
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch
            
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
            self.model.eval()
            self.model.to(self.device)
            print(f"[AG] ✅ Modèle ML chargé (device: {self.device}, threshold: {self.threshold})")
        except ImportError:
            warnings.warn("[AG] ⚠️ transformers/torch non installé — désactivation du ML")
            self.enabled = False
        except Exception as e:
            warnings.warn(f"[AG] ⚠️ Erreur chargement modèle ML: {e} — désactivation")
            self.enabled = False

    @lru_cache(maxsize=10000)
    def predict(self, text: str) -> dict:
        """Analyse un texte et retourne un score de risque."""
        if not self.enabled or self.model is None:
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}
        
        try:
            import torch
            
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                probabilities = torch.softmax(outputs.logits, dim=1)
            
            attack_prob = probabilities[0][1].item()
            
            if attack_prob > self.threshold:
                risk = "HIGH"
            elif attack_prob > self.threshold - 0.15:
                risk = "MEDIUM"
            else:
                risk = "LOW"
            
            return {
                "score": attack_prob,
                "risk": risk,
                "confidence": "high" if attack_prob > 0.9 or attack_prob < 0.1 else "medium"
            }
        except Exception as e:
            warnings.warn(f"[AG] ⚠️ Erreur ML: {e}")
            return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}
