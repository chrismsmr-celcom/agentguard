#!/bin/bash
# Script de déploiement pour Render / Docker

set -e

echo "🚀 Déploiement d'AgentGuard v4.1..."

# Vérification des variables d'environnement
if [ -z "$AGENTGUARD_API_KEY" ]; then
    echo "❌ AGENTGUARD_API_KEY non définie"
    echo "Génération d'une clé..."
    export AGENTGUARD_API_KEY="ag-$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    echo "🔑 Clé générée: $AGENTGUARD_API_KEY"
fi

if [ -z "$DEEPSEEK_API_KEY" ]; then
    echo "⚠️ DEEPSEEK_API_KEY non définie - LLM Judge désactivé"
    export AGENTGUARD_USE_LLM_JUDGE=false
fi

# Construction Docker
echo "📦 Construction de l'image Docker..."
docker compose build

# Démarrage
echo "▶️ Démarrage des services..."
docker compose up -d

# Attente du démarrage
echo "⏳ Attente du démarrage du collector..."
sleep 10

# Test de connexion
echo "🔌 Test de connexion..."
curl -f http://localhost:8080/api/metrics || echo "⚠️ Le collector ne répond pas encore, vérifiez les logs"

echo "✅ Déploiement terminé !"
echo "📊 Dashboard: http://localhost:8080/?key=$AGENTGUARD_API_KEY"
echo "📚 Logs: docker compose logs -f"
