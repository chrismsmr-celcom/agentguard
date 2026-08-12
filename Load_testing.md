# Test de charge — résultats mesurés

Mesuré le 12 août 2026, en conditions proches de la prod : PostgreSQL réel,
Redis pour le rate-limiter, Gunicorn 3 workers × 2 threads (`gthread`),
rate-limit désactivé pour ces tests (déjà validé séparément, voir étape 3
de la roadmap prod-ready) — l'objectif ici est de mesurer la vraie capacité
du serveur, pas le rate-limiter.

Outils : `wrk` (charge soutenue + percentiles) et `ab` (Apache Bench).

## Résultats

| Scénario | Connexions | Req/s | p50 | p90 | p99 | Erreurs |
|---|---|---|---|---|---|---|
| `POST /span` (écriture DB) | 10 | 82.7 | 108ms | 125ms | 153ms | 0 |
| `GET /api/metrics` (lecture + agrégations SQL) | 10 | 60.5 | 130ms | 182ms | 199ms | 0 |
| `POST /span` (forte concurrence) | 50 | 86.7 | 560ms | 608ms | 636ms | 0 |
| `GET /api/metrics` via ab (200 req) | 10 | 49.0 | 158ms | 297ms | 387ms | 0 |

## Ce que ça veut dire concrètement

**Le débit plafonne à ~85 req/s, peu importe la concurrence.** Passer de 10
à 50 connexions simultanées ne fait pas monter le débit — les requêtes
supplémentaires attendent en file, et la latency p50 passe de 108ms à
560ms (×5). Ça veut dire que **le goulot d'étranglement est la config à 3
workers**, pas le réseau ni le client.

**Zéro erreur sur tous les scénarios** — bon signe de robustesse une fois
la race condition de démarrage corrigée (voir plus bas).

## Bug trouvé pendant ce test (pas une estimation — un vrai crash observé)

Le premier lancement de ce test de charge a fait planter le serveur au
démarrage : les 3 workers Gunicorn appellent tous `init_db()` en même
temps, et leurs `CREATE TABLE`/`CREATE INDEX` concurrents sur PostgreSQL
se percutaient, empoisonnant la transaction (`InFailedSqlTransaction`) —
1 worker sur 3 mourait au boot. Invisible avec SQLite ou avec un seul
worker ; seul un vrai test à plusieurs workers contre PostgreSQL l'a
révélé. Corrigé avec un verrou consultatif PostgreSQL (`pg_advisory_lock`)
qui garantit qu'un seul worker exécute vraiment le DDL au démarrage.

## Si tu as besoin de plus de 85 req/s

- **Augmenter le nombre de workers** (`--workers 5` ou plus) — mais chaque
  worker consomme de la RAM ; teste avant de fixer un chiffre en prod.
- **Passer à des workers async** (`gevent` ou `eventlet` au lieu de
  `gthread`) — plus adapté à une charge dominée par de l'attente I/O (DB),
  ce qui est le cas ici (latence >> temps CPU réel par requête).
- **Vérifier le plan PostgreSQL Render** — au-delà d'un certain débit, la
  base elle-même (pas le collector) peut devenir le vrai plafond.

## Comment relancer ce test toi-même

```bash
# Nécessite PostgreSQL + Redis + wrk + ab installés localement
export AGENTGUARD_DB_TYPE=postgres
export DATABASE_URL=postgresql://...
export AGENTGUARD_LIMITER_STORAGE=redis://localhost:6379
export AGENTGUARD_RATE_LIMIT="1000000 per minute"       # désactivé pour mesurer la vraie capacité
export AGENTGUARD_SPAN_RATE_LIMIT="1000000 per minute"

gunicorn --bind 0.0.0.0:9090 --workers 3 --threads 2 wsgi:app &

wrk -t4 -c10 -d15s --latency -H "X-API-Key: ta-cle" http://localhost:9090/api/metrics
```
