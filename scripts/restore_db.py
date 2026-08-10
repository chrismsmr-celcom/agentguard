#!/usr/bin/env python3
"""
Restaure une sauvegarde créée par backup_db.py.

⚠️ ÉCRASE la base actuelle — confirme avant de lancer en prod.

Usage :
    python scripts/restore_db.py backups/agentguard_20260810_120000.dump
    python scripts/restore_db.py backups/agentguard_20260810_120000.db
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

DB_TYPE = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
DB_SQLITE_PATH = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")


def restore_postgres(backup_file: Path):
    if not DATABASE_URL:
        print("[restore] ERREUR: DATABASE_URL non défini.", file=sys.stderr)
        sys.exit(1)
    result = subprocess.run(
        ["pg_restore", "--clean", "--if-exists", "-d", DATABASE_URL, str(backup_file)],
        capture_output=True, text=True,
    )
    # pg_restore renvoie parfois un code non-zéro pour des avertissements
    # bénins (ex: "table does not exist" sur --if-exists) — on affiche le
    # détail mais on ne bloque que sur une absence totale de sortie utile.
    print(result.stderr)
    if result.returncode != 0 and "ERROR" in result.stderr.upper():
        print("[restore] ÉCHEC — voir les erreurs ci-dessus.", file=sys.stderr)
        sys.exit(1)


def restore_sqlite(backup_file: Path):
    if os.path.exists(DB_SQLITE_PATH):
        safety_copy = DB_SQLITE_PATH + ".before_restore"
        shutil.copy(DB_SQLITE_PATH, safety_copy)
        print(f"[restore] Ancienne base sauvegardée par sécurité : {safety_copy}")
    shutil.copy(str(backup_file), DB_SQLITE_PATH)


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/restore_db.py <fichier_de_sauvegarde>", file=sys.stderr)
        sys.exit(1)

    backup_file = Path(sys.argv[1])
    if not backup_file.exists():
        print(f"[restore] ERREUR: {backup_file} introuvable.", file=sys.stderr)
        sys.exit(1)

    confirm = input(f"⚠️  Ceci va écraser la base actuelle avec {backup_file}. Continuer ? [oui/N] ")
    if confirm.strip().lower() not in ("oui", "yes", "y"):
        print("Annulé.")
        sys.exit(0)

    if DB_TYPE == "postgres" and DATABASE_URL:
        restore_postgres(backup_file)
    else:
        restore_sqlite(backup_file)

    print("[restore] ✅ Restauration terminée.")


if __name__ == "__main__":
    main()
