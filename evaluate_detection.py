import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from agentguard_ml import InjectionDetector

# Charger un dataset de test indépendant
test_dataset = load_dataset('csv', data_files='test_dataset.csv')

detector = InjectionDetector()
predictions = []
ground_truth = []

for example in test_dataset:
    pred = detector.predict(example["text"])
    predictions.append(1 if pred["risk"] == "HIGH" else 0)
    ground_truth.append(example["label"])

# Métriques
print("Classification Report:")
print(classification_report(ground_truth, predictions, target_names=["Safe", "Attack"]))

# Matrice de confusion
cm = confusion_matrix(ground_truth, predictions)
print("\nConfusion Matrix:")
print(cm)

# Calcul des métriques clés
tn, fp, fn, tp = cm.ravel()
precision = tp / (tp + fp)
recall = tp / (tp + fn)
accuracy = (tp + tn) / (tp + tn + fp + fn)
f1 = 2 * (precision * recall) / (precision + recall)

print(f"\n✅ Précision: {precision:.2%}")
print(f"✅ Rappel: {recall:.2%}")
print(f"✅ Exactitude: {accuracy:.2%}")
print(f"✅ F1-Score: {f1:.2%}")
