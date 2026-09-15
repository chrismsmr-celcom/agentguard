"""
Script pour ajouter les index de performance manquants à la base de données.
Usage: python scripts/add_db_indexes.py
"""
import os
import sys
import logging

# Ajoute le chemin racine pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.db import get_db, is_postgres
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def add_indexes():
    db = get_db()
    cursor = db.cursor()
    
    indexes = [
        ("idx_spans_org_timestamp", "CREATE INDEX IF NOT EXISTS idx_spans_org_timestamp ON spans(org_id, timestamp DESC)"),
        ("idx_spans_agent_timestamp", "CREATE INDEX IF NOT EXISTS idx_spans_agent_timestamp ON spans(agent_id, timestamp DESC)"),
        ("idx_spans_trace_id", "CREATE INDEX IF NOT EXISTS idx_spans_trace_id ON spans(trace_id)"),
        ("idx_spans_blocked", "CREATE INDEX IF NOT EXISTS idx_spans_blocked ON spans(blocked) WHERE blocked = TRUE"), # Postgres only, ignoré silencieusement par SQLite
    ]
    
    for name, sql in indexes:
        try:
            cursor.execute(sql)
            db.commit()
            logging.info(f"✅ Index créé ou déjà présent : {name}")
        except Exception as e:
            # SQLite ignore le "WHERE" dans les index, on continue
            if "near \"WHERE\"" in str(e) and "SQLite" in str(type(e)):
                logging.warning(f"⚠️ Index {name} partiellement ignoré (fonctionnalité Postgres uniquement)")
            else:
                logging.error(f"❌ Erreur sur l'index {name}: {e}")

if __name__ == "__main__":
    logging.info("🚀 Démarrage de l'optimisation des index de base de données...")
    add_indexes()
    logging.info("✨ Terminé.")
