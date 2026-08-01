# 🔧 Debug — Dashboard à 0

## Problème
Le dashboard affiche 0 partout. Les logs Render montrent des GET (dashboard) mais pas de POST /span (agent).

## Cause la plus probable
Le SDK n'arrive pas à joindre le collector (timeout trop court, mauvaise URL, ou collector en cold start).

## Étapes de debug

### 1. Teste la connexion
```bash
export AGENTGUARD_COLLECTOR_URL=https://agentguard-aqal.onrender.com
python test_connection.py
```

Tu dois voir :
```
[1/3] Health check (/api/metrics)...
   Status: 200
   Body: {...}

[2/3] Envoi d'une span test...
   Status: 201
   ✅ Span reçue!

[3/3] Vérification dans la DB...
   Traces trouvées: 1
   ✅ La span est stockée!
```

### 2. Si le test échoue
- Vérifie que l'URL est correcte (pas de `/` en trop, pas d'espace)
- Vérifie que le service Render est bien "Live" (pas en cold start)
- Ouvre le dashboard dans ton navigateur pour réveiller le service
- Attends 10-20s et relance le test

### 3. Lance l'agent avec le nouveau SDK
```bash
export AGENTGUARD_COLLECTOR_URL=https://agentguard-aqal.onrender.com
export DEEPSEEK_API_KEY=sk-...
python example_deepseek.py
```

Tu dois voir dans le terminal :
```
[AgentGuard] Initialisé — collector: https://agentguard-aqal.onrender.com
[AgentGuard] ✅ Collector connecté (200)
[AgentGuard] 📤 Span envoyée (llm_call, blocked=False)
```

### 4. Rafraîchis le dashboard
Ouvre https://agentguard-aqal.onrender.com/ et rafraîchis (F5).

---

## ⚠️ Limitation SQLite sur Render (Free Tier)

Sur Render gratuit, le filesystem est **éphémère** :
- À chaque **déploiement** → la DB est perdue
- À chaque **redémarrage** → la DB est perdue
- Le service s'**endort** après 15 min d'inactivité → DB perdue au réveil

**Solution pour la démo** : Relance l'agent juste avant la démo.

**Solution pour la prod** : Passer à PostgreSQL (Render offre PostgreSQL gratuit).
