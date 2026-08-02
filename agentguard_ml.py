import os
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from functools import lru_cache

class InjectionDetector:
    def __init__(self, model_path: str = "./agentguard-model", threshold: float = 0.85):
        self.model_path = model_path
        self.threshold = threshold
        
        # Vérifier si le modèle existe, sinon créer un fallback
        if not os.path.exists(model_path):
            print("[AG] ⚠️ Modèle ML non trouvé, utilisation du fallback (regex uniquement)")
            self.model = None
            self.tokenizer = None
            return
            
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.eval()
        
        # Mettre sur GPU si disponible
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        print(f"[AG] ✅ Modèle ML chargé (device: {self.device})")

    @lru_cache(maxsize=10000)  # Cache pour éviter de re-analyser les mêmes prompts
    def predict(self, text: str) -> dict:
        """Analyse un texte et retourne un score de risque."""
        if self.model is None:
            return {"score": 0.0, "risk": "UNKNOWN"}
            
        # Tokenisation
        inputs = self.tokenizer(
            text, 
            return_tensors="pt", 
            truncation=True, 
            max_length=512,
            padding=True
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Prédiction
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            
        # La colonne 1 = probabilité d'être une attaque
        attack_prob = probabilities[0][1].item()
        
        # Détermination du risque
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

    def predict_batch(self, texts: list) -> list:
        """Analyse plusieurs textes en une seule passe (optimisation)."""
        if self.model is None:
            return [{"score": 0.0, "risk": "UNKNOWN"} for _ in texts]
            
        inputs = self.tokenizer(
            texts, 
            return_tensors="pt", 
            truncation=True, 
            max_length=512,
            padding=True
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)
            
        results = []
        for i in range(len(texts)):
            attack_prob = probabilities[i][1].item()
            results.append({
                "score": attack_prob,
                "risk": "HIGH" if attack_prob > self.threshold else "MEDIUM" if attack_prob > self.threshold - 0.15 else "LOW",
                "confidence": "high" if attack_prob > 0.9 or attack_prob < 0.1 else "medium"
            })
        return results

# Singleton pour ne pas recharger le modèle à chaque fois
_detector = None

def get_detector():
    global _detector
    if _detector is None:
        _detector = InjectionDetector(
            model_path=os.environ.get("AGENTGUARD_MODEL_PATH", "./agentguard-model"),
            threshold=float(os.environ.get("AGENTGUARD_ML_THRESHOLD", "0.85"))
        )
    return _detector
