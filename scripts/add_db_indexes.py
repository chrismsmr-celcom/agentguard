import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collector.db import get_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def add_indexes():
    db = get_db()
    cursor = db.cursor()
    
    indexes = [
        ("idx_spans_org_timestamp", "CREATE INDEX IF NOT EXISTS idx_spans_org_timestamp ON spans(org_id, timestamp DESC)"),
        ("idx_spans_agent_timestamp", "CREATE INDEX IF NOT EXISTS idx_spans_agent_timestamp ON spans(agent_id, timestamp DESC)"),
        ("idx_spans_trace_id", "CREATE INDEX IF NOT EXISTS idx_spans_trace_id ON spans(trace_id)"),
    ]
    
    # Note: L'index partiel (WHERE blocked = TRUE) est spécifique à Postgres. 
    # On l'ajoute conditionnellement ou on l'ignore silencieusement sur SQLite.
    indexes.append(("idx_spans_blocked", "CREATE INDEX IF NOT EXISTS idx_spans_blocked ON spans(blocked) WHERE blocked = TRUE"))
    
    for name, sql in indexes:
        try:
            cursor.execute(sql)
            db.commit()
            logging.info(f"✅ Index créé ou déjà présent : {name}")
        except Exception as e:
            if "near \"WHERE\"" in str(e):
                logging.warning(f"⚠️ Index {name} ignoré (fonctionnalité Postgres uniquement, SQLite OK)")
            else:
                logging.error(f"❌ Erreur sur l'index {name}: {e}")

if __name__ == "__main__":
    logging.info("🚀 Optimisation des index de base de données...")
    add_indexes()
    logging.info("✨ Terminé.")
