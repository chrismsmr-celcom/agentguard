# 🐘 Migration PostgreSQL — Instructions

## Pourquoi ?
SQLite sur Render = données perdues à chaque redémarrage.
PostgreSQL = données persistantes, scalable, pro.

## Étape 1 : Créer la base PostgreSQL sur Render

1. Va sur https://dashboard.render.com
2. Clique **"New +"** → **"PostgreSQL"**
3. Nomme-la : `agentguard-db`
4. Plan : **Free** (1 Go, suffisant pour la démo)
5. Crée

## Étape 2 : Connecter la DB au service Web

1. Va sur ton service Web `agentguard-collector`
2. Onglet **Environment**
3. Ajoute cette variable :

```
DATABASE_URL = [copie l'Internal Database URL depuis la page PostgreSQL]
```

Render injecte aussi automatiquement `DATABASE_URL` si tu utilises le Blueprint.

## Étape 3 : Push le nouveau code

```bash
git add .
git commit -m "v3: PostgreSQL + persistence"
git push origin main
```

## Étape 4 : Vérifier

Dans les logs Render, tu dois voir :
```
[AG] ✅ PostgreSQL initialisé
```

Et plus jamais :
```
[AG] ✅ SQLite initialisé
```

## En local (développement)

Sans rien changer, le collector utilise SQLite :
```bash
python collector.py
# → [AG] ✅ SQLite initialisé
```

Pour forcer PostgreSQL en local (optionnel) :
```bash
export DATABASE_URL="postgresql://user:pass@localhost:5432/agentguard"
export AGENTGUARD_DB_TYPE=postgres
python collector.py
```

## ⚠️ Important

La base PostgreSQL Render gratuite s'endort après 90 jours d'inactivité.
Pour la prod, passe au plan Starter ($7/mois) ou supérieur.
